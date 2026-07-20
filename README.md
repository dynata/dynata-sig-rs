# dynata-sig-rs

A Rust library for Dynata request-signing primitives. It provides the following:

* URL canonicalization for signing
* Signing-string generation (SHA256 lowercase hex of METHOD + canonical_url + body)
* Signature generation via the 3-step HMAC-SHA256 chain

### Credentials

Before sending signed requests you will need credentials for Dynata APIs. These consist of:

- **Access key**: used locally to compute the `dynata-signature` and also sent in the `dynata-access-key` request
  header.
- **Secret key**: never sent as a header; used locally to compute the `dynata-signature`.

### Installation

```bash
cargo add dynata-sig
```

#### Features

* hyper (optional): Add support for applying signatures to a hyper request builder
* reqwest (optional): Add support for applying signatures to a reqwest request builder

### Usage

```rust
use dynata_sig::signature::Signer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let uri: http::Uri = "https://example.dynata.com/endpoint?b=2&b=1&a=9".try_into()?;
    let canonical_uri: CanonicalUri = uri.into();

    let body = "{}";

    let signing_string = canonical_uri.build_signing_string(&http::Method::POST, body);

    let access_key = std::env::var("DYNATA_ACCESS_KEY")?;
    let secret_key = std::env::var("DYNATA_SECRET_KEY")?;
    let signature = signing_string.sign(
        &(access_key, secret_key).into(),
        &"2025-12-31T23:59:59.000Z".parse()?,
    )?;

    let request = reqwest::Client::new()
        .post(canonical_uri.to_string())
        .body(body)
        .header("dynata-expiration", signature.expiration)
        .header("dynata-access-key", signature.access_key)
        .header("dynata-signature", signature.value)
        .send()
        .await?;

    Ok(())
}
```

## Algorithm

### Generating Signing Strings

Each Dynata signature starts from a signing string, which is built from:

`{METHOD}{URI}{BODY}`

with no delimiter between segments, then hashed as SHA-256 and encoded as lowercase hex.

### Method

Use the exact HTTP method sent on the wire (`GET`, `POST`, `DELETE`, etc.).

### URI

Use the URI (`scheme + host + path + query`) in canonical form.

- Scheme: advertised scheme of the receiving application.
- Host: domain name only (do not include port).
- Path: target resource path, including the leading `/`.
- Query: use a canonical query string.

Canonical query construction:

1. Sort parameter names by character code point ascending.
2. URI-encode each name and value using RFC 3986 rules.
3. Do not encode unreserved characters: `A-Z`, `a-z`, `0-9`, `-`, `_`, `.`, `~`.
4. Percent-encode all other characters as uppercase hex (`%XY`).
5. Encode spaces as `%20` (never `+`).
6. Build pairs as `name=value`, then join with `&`.
7. Use an empty string when a parameter has no value.

### Body

Use the exact body text/bytes sent with the request. Whitespace, ordering, and encoding must be preserved exactly.

### Signature Computation

After generating the signing string, compute the signature using a three-step HMAC-SHA256 chain:

1. HMAC with expiration timestamp as key and signing string as message.
2. HMAC with access key as key and step 1 output as message.
3. HMAC with secret key as key and step 2 output as message.

Implementation notes:

- The final signing string digest is always a 64-character lowercase SHA-256 hex value.
- If there is no body, use an empty body segment.
- Use UTF-8 for all key and message conversions.
- Use lowercase hex output for each HMAC digest.
- Reuse the exact RFC3339 expiration value from the `dynata-expiration` header.

## Contribution Notes

### Run tests

```bash
cargo test
```
