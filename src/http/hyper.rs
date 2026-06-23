use hyper::http::request::Builder;

use crate::signature::{Apply, Signature};

impl Apply<Signature> for Builder {
    fn apply(self, subject: Signature) -> Self {
        self.header("dynata-expiration", subject.expiration)
            .header("dynata-access-key", subject.access_key)
            .header("dynata-signature", subject.value)
    }
}
