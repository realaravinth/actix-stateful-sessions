use std::{cell::RefCell, mem, rc::Rc};

use actix_web::{
    dev::{Extensions, Payload, RequestHead, ServiceRequest, ServiceResponse},
    Error, FromRequest, HttpMessage, HttpRequest,
};
use futures_util::future::{ok, Ready};

/// Extraction of a [`Session`] object.
pub trait UserSession {
    /// Extract the [`Session`] object
    fn get_session(&self) -> Session;
}

impl UserSession for HttpRequest {
    fn get_session(&self) -> Session {
        Session::get_session(&mut *self.extensions_mut())
    }
}

impl UserSession for ServiceRequest {
    fn get_session(&self) -> Session {
        Session::get_session(&mut *self.extensions_mut())
    }
}

impl UserSession for RequestHead {
    fn get_session(&self) -> Session {
        Session::get_session(&mut *self.extensions_mut())
    }
}

/// Status of a [`Session`].
#[derive(PartialEq, Clone, Debug)]
pub enum SessionStatus {
    /// Session has been updated and requires a new persist operation.
    Changed,

    /// Session is flagged for deletion and should be removed from client and server.
    ///
    /// Most operations on the session after purge flag is set should have no effect.
    Purged,

    /// Session is flagged for refresh.
    ///
    /// For example, when using a backend that has a TTL (time-to-live) expiry on the session entry,
    /// the session will be refreshed even if no data inside it has changed. The client may also
    /// be notified of the refresh.
    Renewed,

    /// Session is unchanged from when last seen (if exists).
    ///
    /// This state also captures new (previously unissued) sessions such as a user's first
    /// site visit.
    Unchanged,
}

impl Default for SessionStatus {
    fn default() -> SessionStatus {
        SessionStatus::Unchanged
    }
}

#[derive(Default)]
struct SessionInner {
    id: String,
    status: SessionStatus,
}

pub struct Session(Rc<RefCell<SessionInner>>);

impl Session {
    /// Get a `value` from the session.
    pub fn get(&self) -> String {
        self.0.borrow().id.clone()
    }
    //
    //    /// Inserts a key-value pair into the session.
    //    ///
    //    /// Any serializable value can be used and will be encoded as JSON in session data, hence why
    //    /// only a reference to the value is taken.
    //    pub(crate) fn set(&self, id: impl Into<String>) {
    //        let mut inner = self.0.borrow_mut();
    //
    //        if inner.status != SessionStatus::Purged {
    //            inner.status = SessionStatus::Changed;
    //            inner.id = id.into();
    //        }
    //    }
    //
    /// Clear the session.
    pub fn clear(&self) -> Option<String> {
        let mut inner = self.0.borrow_mut();

        if inner.status != SessionStatus::Purged {
            inner.status = SessionStatus::Changed;
            Some(mem::take(&mut inner.id))
        } else {
            None
        }
    }

    /// Removes session both client and server side.
    pub fn purge(&self) {
        let mut inner = self.0.borrow_mut();
        inner.status = SessionStatus::Purged;
        inner.id.clear();
    }

    /// Renews the session key, assigning existing session state to new key.
    pub fn renew(&self) {
        let mut inner = self.0.borrow_mut();

        if inner.status != SessionStatus::Purged {
            inner.status = SessionStatus::Renewed;
        }
    }

    fn get_session(extensions: &mut Extensions) -> Session {
        if let Some(s_impl) = extensions.get::<Rc<RefCell<SessionInner>>>() {
            return Session(Rc::clone(&s_impl));
        }
        let inner = Rc::new(RefCell::new(SessionInner::default()));
        extensions.insert(inner.clone());
        Session(inner)
    }

    pub(crate) fn set_session(req: &mut ServiceRequest, id: impl Into<String>) {
        let session = Session::get_session(&mut *req.extensions_mut());
        let mut inner = session.0.borrow_mut();
        inner.id = id.into();
    }

    /// Returns session status and iterator of key-value pairs of changes.
    pub fn get_changes<B>(res: &mut ServiceResponse<B>) -> (SessionStatus, String) {
        if let Some(s_impl) = res
            .request()
            .extensions()
            .get::<Rc<RefCell<SessionInner>>>()
        {
            let id = mem::take(&mut s_impl.borrow_mut().id);
            (s_impl.borrow().status.clone(), id)
        } else {
            (SessionStatus::Unchanged, String::new())
        }
    }
}

impl FromRequest for Session {
    type Error = Error;
    type Future = Ready<Result<Session, Error>>;
    type Config = ();

    #[inline]
    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        ok(Session::get_session(&mut *req.extensions_mut()))
    }
}

#[cfg(test)]
mod tests {
    use actix_web::test;

    use super::*;

    const ID: &str = "session";

    #[test]
    fn session() {
        let mut req = test::TestRequest::default().to_srv_request();

        Session::set_session(&mut req, ID);
        let session = Session::get_session(&mut *req.extensions_mut());
        let res = session.get();
        assert_eq!(res, ID);
    }

    #[test]
    fn get_session() {
        let mut req = test::TestRequest::default().to_srv_request();

        Session::set_session(&mut req, ID);

        let session = req.get_session();
        let res = session.get();
        assert_eq!(res, ID);
    }

    #[test]
    fn get_session_from_request_head() {
        let mut req = test::TestRequest::default().to_srv_request();

        Session::set_session(&mut req, ID);

        let session = req.head_mut().get_session();
        let res = session.get();
        assert_eq!(res, ID);
    }

    #[test]
    fn purge_session() {
        let req = test::TestRequest::default().to_srv_request();
        let session = Session::get_session(&mut *req.extensions_mut());
        assert_eq!(session.0.borrow().status, SessionStatus::Unchanged);
        session.purge();
        assert_eq!(session.0.borrow().status, SessionStatus::Purged);
    }

    #[test]
    fn renew_session() {
        let req = test::TestRequest::default().to_srv_request();
        let session = Session::get_session(&mut *req.extensions_mut());
        assert_eq!(session.0.borrow().status, SessionStatus::Unchanged);
        session.renew();
        assert_eq!(session.0.borrow().status, SessionStatus::Renewed);
    }
}
