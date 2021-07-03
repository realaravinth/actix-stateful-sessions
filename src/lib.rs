//! Cookie based sessions. See docs for [`CookieSession`].

use std::error::Error as StdError;
#[allow(unused_imports)]
#[allow(dead_code)]
use std::{collections::HashMap, rc::Rc};

use actix_service::{Service, Transform};
use actix_web::body::{AnyBody, MessageBody};
use actix_web::cookie::{Cookie, CookieJar, SameSite};
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::http::{header::SET_COOKIE, HeaderValue};
use actix_web::{Error, ResponseError};
use derive_more::Display;
use futures_util::future::{ok, FutureExt as _, LocalBoxFuture, Ready};
use time::{Duration, OffsetDateTime};

mod session;

pub use session::{Session, SessionStatus};

const DEFAULT_COOKIE_NAME: &str = "actix-session-ID";
const DEFAULT_SESSION_ID_LEN: usize = 32;

/// Errors that can occur during handling cookie session
#[derive(Debug, Display)]
pub enum CookieSessionError {
    /// Size of the serialized session is greater than 4000 bytes.
    #[display(fmt = "Size of the serialized session is greater than 4000 bytes.")]
    Overflow,
}

impl ResponseError for CookieSessionError {}

pub struct CookieConfig {
    name: String,
    path: String,
    domain: Option<String>,
    secure: bool,
    http_only: bool,
    max_age: Option<Duration>,
    expires_in: Option<Duration>,
    same_site: Option<SameSite>,
}

impl Default for CookieConfig {
    fn default() -> Self {
        Self {
            name: DEFAULT_COOKIE_NAME.into(),
            path: "/".to_owned(),
            domain: None,
            secure: true,
            http_only: true,
            max_age: None,
            expires_in: None,
            same_site: None,
        }
    }
}

impl CookieConfig {
    fn set_cookie<B>(&self, res: &mut ServiceResponse<B>, value: String) -> Result<(), Error> {
        if value.len() > 4064 {
            return Err(CookieSessionError::Overflow.into());
        }

        let mut cookie = Cookie::new(self.name.clone(), value);
        cookie.set_path(self.path.clone());
        cookie.set_secure(self.secure);
        cookie.set_http_only(self.http_only);

        if let Some(ref domain) = self.domain {
            cookie.set_domain(domain.clone());
        }

        if let Some(expires_in) = self.expires_in {
            cookie.set_expires(OffsetDateTime::now_utc() + expires_in);
        }

        if let Some(max_age) = self.max_age {
            cookie.set_max_age(max_age);
        }

        if let Some(same_site) = self.same_site {
            cookie.set_same_site(same_site);
        }

        let mut jar = CookieJar::new();
        jar.add(cookie);
        for cookie in jar.delta() {
            let val = HeaderValue::from_str(&cookie.encoded().to_string())?;
            res.headers_mut().append(SET_COOKIE, val);
        }

        Ok(())
    }

    /// invalidates session cookie
    fn remove_cookie<B>(&self, res: &mut ServiceResponse<B>) -> Result<(), Error> {
        let mut cookie = Cookie::named(self.name.clone());
        cookie.set_path(self.path.clone());
        cookie.set_value("");
        cookie.set_max_age(Duration::zero());
        cookie.set_expires(OffsetDateTime::now_utc() - Duration::days(365));

        let val = HeaderValue::from_str(&cookie.to_string())?;
        res.headers_mut().append(SET_COOKIE, val);

        Ok(())
    }

    fn load(&self, req: &ServiceRequest) -> (bool, String) {
        if let Ok(cookies) = req.cookies() {
            for cookie in cookies.iter() {
                if cookie.name() == self.name {
                    let mut jar = CookieJar::new();
                    jar.add_original(cookie.clone());

                    let cookie_opt = jar.get(&self.name);

                    if let Some(cookie) = cookie_opt {
                        return (false, cookie.value().to_owned());
                    }
                }
            }
        }

        (true, String::new())
    }
}

#[derive(Default)]
pub struct CookieSession(Rc<CookieConfig>);

impl CookieSession {
    /// Sets the `path` field in the session cookie being built.
    pub fn path<S: Into<String>>(mut self, value: S) -> CookieSession {
        Rc::get_mut(&mut self.0).unwrap().path = value.into();
        self
    }

    /// Sets the `name` field in the session cookie being built.
    pub fn name<S: Into<String>>(mut self, value: S) -> CookieSession {
        Rc::get_mut(&mut self.0).unwrap().name = value.into();
        self
    }

    /// Sets the `domain` field in the session cookie being built.
    pub fn domain<S: Into<String>>(mut self, value: S) -> CookieSession {
        Rc::get_mut(&mut self.0).unwrap().domain = Some(value.into());
        self
    }

    /// Sets the `secure` field in the session cookie being built.
    ///
    /// If the `secure` field is set, a cookie will only be transmitted when the
    /// connection is secure - i.e. `https`
    pub fn secure(mut self, value: bool) -> CookieSession {
        Rc::get_mut(&mut self.0).unwrap().secure = value;
        self
    }

    /// Sets the `http_only` field in the session cookie being built.
    pub fn http_only(mut self, value: bool) -> CookieSession {
        Rc::get_mut(&mut self.0).unwrap().http_only = value;
        self
    }

    /// Sets the `same_site` field in the session cookie being built.
    pub fn same_site(mut self, value: SameSite) -> CookieSession {
        Rc::get_mut(&mut self.0).unwrap().same_site = Some(value);
        self
    }

    /// Sets the `max-age` field in the session cookie being built.
    pub fn max_age(self, seconds: i64) -> CookieSession {
        self.max_age_time(Duration::seconds(seconds))
    }

    /// Sets the `max-age` field in the session cookie being built.
    pub fn max_age_time(mut self, value: time::Duration) -> CookieSession {
        Rc::get_mut(&mut self.0).unwrap().max_age = Some(value);
        self
    }

    /// Sets the `expires` field in the session cookie being built.
    pub fn expires_in(self, seconds: i64) -> CookieSession {
        self.expires_in_time(Duration::seconds(seconds))
    }

    /// Sets the `expires` field in the session cookie being built.
    pub fn expires_in_time(mut self, value: Duration) -> CookieSession {
        Rc::get_mut(&mut self.0).unwrap().expires_in = Some(value);
        self
    }
}

impl<S, B> Transform<S, ServiceRequest> for CookieSession
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>>,
    S::Future: 'static,
    S::Error: 'static,
    B: MessageBody + 'static,
    B::Error: StdError,
{
    type Response = ServiceResponse;
    type Error = S::Error;
    type InitError = ();
    type Transform = StatefulSessionMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(StatefulSessionMiddleware {
            service,
            inner: self.0.clone(),
        })
    }
}

/// Cookie based session middleware.
pub struct StatefulSessionMiddleware<S> {
    service: S,
    inner: Rc<CookieConfig>,
}

impl<S, B> Service<ServiceRequest> for StatefulSessionMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>>,
    S::Future: 'static,
    S::Error: 'static,
    B: MessageBody + 'static,
    B::Error: StdError,
{
    type Response = ServiceResponse;
    type Error = S::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    actix_service::forward_ready!(service);

    /// On first request, a new session cookie is returned in response, regardless
    /// of whether any session state is set.  With subsequent requests, if the
    /// session state changes, then set-cookie is returned in response.  As
    /// a user logs out, call session.purge() to set SessionStatus accordingly
    /// and this will trigger removal of the session cookie in the response.
    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        let inner = self.inner.clone();
        let (is_new, state) = self.inner.load(&req);
        let prolong_expiration = self.inner.expires_in.is_some();
        Session::set_session(&mut req, state);

        let fut = self.service.call(req);

        async move {
            let mut res = fut.await?;

            let result = match Session::get_changes(&mut res) {
                (SessionStatus::Changed, id) | (SessionStatus::Renewed, id) => {
                    inner.set_cookie(&mut res, id)
                }

                (SessionStatus::Unchanged, id) if prolong_expiration => {
                    inner.set_cookie(&mut res, id)
                }

                // set a new session cookie upon first request (new client)
                (SessionStatus::Unchanged, _) => {
                    if is_new {
                        let id = get_random(DEFAULT_SESSION_ID_LEN);
                        inner.set_cookie(&mut res, id)
                    } else {
                        Ok(())
                    }
                }

                (SessionStatus::Purged, _) => {
                    let _ = inner.remove_cookie(&mut res);
                    Ok(())
                }
            };

            match result {
                Ok(()) => Ok(res.map_body(|_, body| AnyBody::from_message(body))),
                Err(error) => Ok(res.error_response(error)),
            }
        }
        .boxed_local()
    }
}

fn get_random(len: usize) -> String {
    use rand::{distributions::Alphanumeric, rngs::ThreadRng, thread_rng, Rng};
    use std::iter;

    let mut rng: ThreadRng = thread_rng();

    iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .map(char::from)
        .take(len)
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web, App};

    #[actix_rt::test]
    async fn cookie_session() {
        let app = test::init_service(
            App::new()
                .wrap(CookieSession::default().secure(false))
                .service(web::resource("/").to(|ses: Session| async move {
                    let session = ses.get();
                    session
                })),
        )
        .await;

        let request = test::TestRequest::get().to_request();
        let response = app.call(request).await.unwrap();
        assert!(response
            .response()
            .cookies()
            .any(|c| c.name() == DEFAULT_COOKIE_NAME));
    }

    #[actix_rt::test]
    async fn cookie_session_extractor() {
        let app = test::init_service(
            App::new()
                .wrap(CookieSession::default().secure(false))
                .service(web::resource("/").to(|ses: Session| async move {
                    let session = ses.get();
                    session
                })),
        )
        .await;

        let request = test::TestRequest::get().uri("/").to_request();
        let response = app.call(request).await.unwrap();

        assert!(response
            .response()
            .cookies()
            .any(|c| c.name() == DEFAULT_COOKIE_NAME));
    }

    //   #[actix_rt::test]
    //   async fn basics() {
    //       let app = test::init_service(
    //           App::new()
    //               .wrap(
    //                   CookieSession::default()
    //                       .path("/test/")
    //                       .name("actix-test")
    //                       .domain("localhost")
    //                       .http_only(true)
    //                       .same_site(SameSite::Lax)
    //                       .max_age(100),
    //               )
    //               .service(web::resource("/").to(|ses: Session| async move {
    //                   let _ = ses.get();
    //                   "test"
    //               }))
    //               .service(web::resource("/test/").to(|ses: Session| async move {
    //                   let val = ses.get();
    //                   format!("counter: {}", val)
    //               })),
    //       )
    //       .await;

    //       let request = test::TestRequest::get().to_request();
    //       let response = app.call(request).await.unwrap();
    //       let cookie = response
    //           .response()
    //           .cookies()
    //           .find(|c| c.name() == "actix-test")
    //           .unwrap()
    //           .clone();
    //       assert_eq!(cookie.path().unwrap(), "/test/");

    //       let request = test::TestRequest::with_uri("/test/")
    //           .cookie(cookie)
    //           .to_request();
    //       let body = test::read_response(&app, request).await;
    //       assert_eq!(body, Bytes::from_static(b"counter: 100"));
    //   }

    #[actix_rt::test]
    async fn prolong_expiration() {
        let app = test::init_service(
            App::new()
                .wrap(CookieSession::default().secure(false).expires_in(60))
                .service(web::resource("/").to(|ses: Session| async move {
                    let _ = ses.get();
                    "test"
                }))
                .service(web::resource("/test/").to(|| async move { "no-changes-in-session" })),
        )
        .await;

        let request = test::TestRequest::get().to_request();
        let response = app.call(request).await.unwrap();
        let expires_1 = response
            .response()
            .cookies()
            .find(|c| c.name() == DEFAULT_COOKIE_NAME)
            .expect("Cookie is set")
            .expires()
            .expect("Expiration is set")
            .datetime()
            .expect("Expiration is a datetime");

        actix_rt::time::sleep(std::time::Duration::from_secs(1)).await;

        let request = test::TestRequest::with_uri("/test/").to_request();
        let response = app.call(request).await.unwrap();
        let expires_2 = response
            .response()
            .cookies()
            .find(|c| c.name() == DEFAULT_COOKIE_NAME)
            .expect("Cookie is set")
            .expires()
            .expect("Expiration is set")
            .datetime()
            .expect("Expiration is a datetime");

        assert!(expires_2 - expires_1 >= Duration::seconds(1));
    }
}
