/*!
Types for constructing signed http requests
*/
use std::collections::BTreeMap;
use std::fmt::Display;

use crate::hash::ToHash;
use http::uri::{PathAndQuery, Scheme};
use http::{Method, Uri};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode, percent_encode};
use sha2::Sha256;

use crate::signature::{Apply, Signature};

#[cfg(feature = "hyper")]
mod hyper;
#[cfg(feature = "reqwest")]
mod reqwest;

const REPLACEMENTS: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Construct a signing string for http requests
pub fn construct_signing_string<U: Display + ?Sized, B: Display + ?Sized>(
    method: &Method,
    canonical_url: &U,
    body: &B,
) -> String {
    format!("{method}{canonical_url}{body}").to_hash::<Sha256>()
}

/// Convert a well-formed Uri into a canonically-ordered representation
pub fn canonicalize_uri(uri: &Uri) -> Uri {
    let query = form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes())
        .fold(BTreeMap::new(), |mut acc, (key, value)| {
            acc.insert(key, value);

            acc
        })
        .iter()
        .map(|(key, value)| {
            format!(
                "{}={}",
                percent_encode(
                    percent_decode(key.as_bytes())
                        .decode_utf8()
                        .unwrap()
                        .as_bytes(),
                    REPLACEMENTS
                ),
                percent_encode(
                    percent_decode(value.as_bytes())
                        .decode_utf8()
                        .unwrap()
                        .as_bytes(),
                    REPLACEMENTS
                )
            )
        })
        .collect::<Vec<String>>();

    Uri::builder()
        .scheme(uri.scheme().cloned().unwrap_or(Scheme::HTTPS))
        .authority(uri.host().unwrap_or_default())
        .path_and_query(format!("{}?{}", uri.path(), query.join("&")))
        .build()
        .unwrap()
}

impl Apply<Signature> for Uri {
    fn apply(self, subject: Signature) -> Self {
        let mut parts = self.into_parts();
        if let Some(ref mut pq) = parts.path_and_query {
            let mut query = form_urlencoded::parse(pq.query().unwrap_or_default().as_bytes())
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<String>>();

            query.push(format!("dynata-expiration={}", subject.expiration));
            query.push(format!("dynata-access-key={}", subject.access_key));
            query.push(format!("dynata-signature={}", subject.value));

            *pq = PathAndQuery::from_maybe_shared(format!("{}?{}", pq.path(), query.join("&")))
                .unwrap()
        }

        //SAFETY: Parts came from a valid Uri, and the modifications above wouldn't invalidate it
        Uri::from_parts(parts).unwrap()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::signature::Signer;

    #[test]
    fn signing_string_with_all_parts() {
        let result = construct_signing_string(&Method::GET, "some string", "some other string");
        let expected = "GETsome stringsome other string".to_hash::<Sha256>();

        assert_eq!(expected, result);
    }

    #[test]
    fn signing_string_with_no_body() {
        let result = construct_signing_string(&Method::GET, "some string", "");
        let expected = "GETsome string".to_hash::<Sha256>();

        assert_eq!(expected, result);
    }

    #[test]
    fn canonical_uri_discards_port() {
        let uri = Uri::builder()
            .scheme("https")
            .authority("example.com:1234")
            .path_and_query("/something?param=1")
            .build()
            .unwrap();

        let canon = canonicalize_uri(&uri);

        let expected = "https://example.com/something?param=1";
        assert_ne!(expected, uri.to_string());
        assert_eq!(expected, canon.to_string());
    }

    #[test]
    fn canonical_uri_adds_query_marker() {
        let uri = Uri::builder()
            .scheme("https")
            .authority("example.com")
            .path_and_query("/")
            .build()
            .unwrap();

        let canon = canonicalize_uri(&uri);

        let expected = "https://example.com/?";
        assert_ne!(expected, uri.to_string());
        assert_eq!(expected, canon.to_string());
    }

    #[test]
    fn canonical_uri_sorts_params() {
        let uri = Uri::builder()
            .scheme("https")
            .authority("example.com")
            .path_and_query("/?c=3&b=2&d=4&a=1")
            .build()
            .unwrap();

        let canon = canonicalize_uri(&uri);

        let expected = "https://example.com/?a=1&b=2&c=3&d=4";
        assert_ne!(expected, uri.to_string());
        assert_eq!(expected, canon.to_string());
    }

    #[test]
    fn canonical_uri_deduplicates_params() {
        let uri = Uri::builder()
            .scheme("https")
            .authority("example.com")
            .path_and_query("/?a=2&a=1&a=3")
            .build()
            .unwrap();

        let canon = canonicalize_uri(&uri);

        let expected = "https://example.com/?a=3";
        assert_ne!(expected, uri.to_string());
        assert_eq!(expected, canon.to_string());
    }

    #[test]
    fn canonical_uri_encodes_params() {
        let uri = Uri::builder()
            .scheme("https")
            .authority("example.com")
            .path_and_query("/?kéy=valüe")
            .build()
            .unwrap();

        let canon = canonicalize_uri(&uri);

        let expected = "https://example.com/?k%C3%A9y=val%C3%BCe";
        assert_ne!(expected, uri.to_string());
        assert_eq!(expected, canon.to_string());
    }

    #[test]
    fn canonical_uri_avoids_double_encoding_params() {
        let uri = Uri::builder()
            .scheme("https")
            .authority("example.com")
            .path_and_query("/?k%C3%A9y=val%C3%BCe")
            .build()
            .unwrap();

        let canon = canonicalize_uri(&uri);

        let expected = "https://example.com/?k%C3%A9y=val%C3%BCe";
        assert_eq!(expected, uri.to_string());
        assert_eq!(expected, canon.to_string());
    }

    #[test]
    fn apply_signature_uri_with_params() {
        let uri = Uri::builder()
            .scheme("https")
            .authority("example.com")
            .path_and_query("/?some=thing")
            .build()
            .unwrap();

        let uri = canonicalize_uri(&uri);
        let signing_string = construct_signing_string(&Method::GET, &uri, "");
        let signature = signing_string
            .sign(
                &("access-key".into(), "secret-key".into()).into(),
                &"2021-03-30T14:17:29.208Z".parse().unwrap(),
            )
            .unwrap();

        let signed_uri = uri.apply(signature);

        assert_eq!(
            "https://example.com/?some=thing&dynata-expiration=2021-03-30T14:17:29.208Z&dynata-access-key=access-key&dynata-signature=163ad31084914fdce4dd918c06544d2f25fa7c37104fb1ae74ab6904d3688fd6",
            signed_uri.to_string()
        );
    }

    #[test]
    fn apply_signature_uri_without_params() {
        let uri = Uri::builder()
            .scheme("https")
            .authority("example.com")
            .path_and_query("/")
            .build()
            .unwrap();

        let uri = canonicalize_uri(&uri);
        let signing_string = construct_signing_string(&Method::GET, &uri, "");
        let signature = signing_string
            .sign(
                &("access-key".into(), "secret-key".into()).into(),
                &"2021-03-30T14:17:29.208Z".parse().unwrap(),
            )
            .unwrap();

        let signed_uri = uri.apply(signature);

        assert_eq!(
            "https://example.com/?dynata-expiration=2021-03-30T14:17:29.208Z&dynata-access-key=access-key&dynata-signature=cde53f89fb6f923f7c74dff99227841477897f6dd81d7b7b909b2090412f22f7",
            signed_uri.to_string()
        );
    }
}
