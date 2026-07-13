/*!
Types for constructing signed http requests
*/
use std::collections::BTreeMap;
use std::fmt::Display;

use crate::hash::ToHash;
use http::uri::Scheme;
use http::{Method, Uri};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode, percent_encode};
use sha2::Sha256;

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
    method: Method,
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn signing_string_with_all_parts() {
        let result = construct_signing_string(Method::GET, "some string", "some other string");
        let expected = "GETsome stringsome other string".to_hash::<Sha256>();

        assert_eq!(expected, result);
    }

    #[test]
    fn signing_string_with_no_body() {
        let result = construct_signing_string(Method::GET, "some string", "");
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
}
