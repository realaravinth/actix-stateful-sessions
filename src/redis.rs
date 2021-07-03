use redis_glue::redis::Cmd;
use redis_glue::redis::FromRedisValue;
use redis_glue::redis::RedisError;
//use redis_glue::redis::SaveResult;
use derive_more::Display;
use derive_more::Error;
use redis_glue::{Redis, RedisConfig};

use serde::{de::DeserializeOwned, Serialize};
use serde_json::Error as JsonError;

pub struct Client {
    redis: Redis,
}

const REDIS: &str = "redis://127.0.0.1";

#[derive(Display, Error, Debug)]
pub enum SaveError {
    #[display(fmt = "{}", _0)]
    JsonError(JsonError),
    #[display(fmt = "{}", _0)]
    RedisError(RedisError),
}

impl From<JsonError> for SaveError {
    fn from(e: JsonError) -> Self {
        Self::JsonError(e)
    }
}

impl From<RedisError> for SaveError {
    fn from(e: RedisError) -> Self {
        Self::RedisError(e)
    }
}

pub type SaveResult<T> = Result<T, SaveError>;

impl Client {
    pub async fn new(redis: RedisConfig) -> SaveResult<Self> {
        let redis = Redis::new(redis).await?;
        Ok(Self { redis })
    }

    pub async fn set<V>(&mut self, name: &str, k: &str, v: &V) -> SaveResult<()>
    where
        V: Serialize,
    {
        let v = serde_json::to_string(v)?;

        let conn = self.redis.get_client();
        let mut cmd = Cmd::hset(name, k, v);
        let _: () = conn.exec(&mut cmd).await?;
        Ok(())
    }

    pub async fn get<R>(&mut self, name: &str, k: &str) -> SaveResult<R>
    where
        R: FromRedisValue,
    {
        let conn = self.redis.get_client();
        let mut cmd = Cmd::hget(name, k);
        Ok(conn.exec(&mut cmd).await?)
    }

    pub async fn get_serialzed<R>(&mut self, name: &str, k: &str) -> SaveResult<R>
    where
        R: DeserializeOwned,
    {
        let conn = self.redis.get_client();
        let mut cmd = Cmd::hget(name, k);
        let res: String = conn.exec(&mut cmd).await?;
        let res: R = serde_json::from_str(&res)?;
        Ok(res)
    }

    //    pub async fn get_all(&mut self, name: &str) -> SaveResult<()> {
    //        let conn = self.redis.get_client();
    //        let mut cmd = Cmd::hgetall(name);
    //        let res: String = conn.exec(&mut cmd).await?;
    //        Ok(())
    //    }
    //
    //    pub async fn set_multiple(&mut self, name: &str, kv: &Vec<(&str, &str)>) -> SaveResult<()> {
    //        let conn = self.redis.get_client();
    //        let mut cmd = Cmd::hset_multiple(name, kv);
    //        let _: () = conn.exec(&mut cmd).await?;
    //        Ok(())
    //    }

    pub async fn purge(&mut self, name: &str) -> SaveResult<()> {
        let conn = self.redis.get_client();
        let mut cmd = Cmd::del(name);
        let _: () = conn.exec(&mut cmd).await?;
        Ok(())
    }

    pub async fn remove(&mut self, name: &str, k: &str) -> SaveResult<()> {
        let conn = self.redis.get_client();
        let mut cmd = Cmd::hdel(name, k);
        let _: () = conn.exec(&mut cmd).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SSID: &str = "session_id";

    use redis_glue::redis::Value;

    #[actix_rt::test]
    async fn redis_works() {
        let mut client = Client::new(RedisConfig::Single(REDIS.into()))
            .await
            .unwrap();
        let val = ("test", 1);
        client.set(SSID, &val.0, &val.1).await.unwrap();
        let res: usize = client.get_serialzed(SSID, &val.0).await.unwrap();
        assert_eq!(res, val.1);
        client.remove(SSID, val.0).await.unwrap();
        let res: Value = client.get(SSID, &val.0).await.unwrap();
        assert_eq!(res, Value::Nil);

        client.purge(SSID).await.unwrap();
        let res: Value = client.get(SSID, &val.0).await.unwrap();
        assert_eq!(res, Value::Nil);
    }
}
