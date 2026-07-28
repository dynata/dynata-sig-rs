/*!
A [Provider] that acquires Dynata credentials from environment variables.
*/

use std::env::VarError;

use crate::provider::{Error, Provider};
use crate::signature::Key;

/// Load credentials from environment variables.
///
/// Uses the following variables:
/// - `DYNATA_ACCESS_KEY`
/// - `DYNATA_SECRET_KEY`
#[derive(Debug, Copy, Clone)]
pub struct Environment;

impl Provider for Environment {
    fn credentials(&self) -> Result<Key, Error> {
        let access_key = std::env::var("DYNATA_ACCESS_KEY")?;
        let secret_key = std::env::var("DYNATA_SECRET_KEY")?;

        Ok(Key::new(access_key, secret_key))
    }
}

impl From<VarError> for Error {
    fn from(err: VarError) -> Self {
        match err {
            VarError::NotPresent => Self::Missing("environment variable not set".into()),
            e @ VarError::NotUnicode(_) => Self::Unknown(e.into()),
        }
    }
}
