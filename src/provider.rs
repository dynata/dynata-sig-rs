/*!
Providers that can acquire Dynata credentials in various ways.
*/

use std::fmt::{Debug, Display, Formatter};

use crate::signature::Key;

pub mod chain;
pub mod environment;
pub mod profile;

/// An object that can load a Dynata [Key] pair from some source.
pub trait Provider: Send + Sync + Debug {
    /// Load credentials from a configured source.
    fn credentials(&self) -> Result<Key, Error>;
}

/// Acquire credentials using the default chain provider configuration.
pub fn credentials() -> Result<Key, Error> {
    chain::Builder::default()
        .add_provider(environment::Environment)
        .add_provider(profile::Profile::default())
        .build()
        .credentials()
}

/// Errors returned when a provider fails.
#[derive(Debug)]
pub enum Error {
    /// The provider was unable to locate credentials in the configured location. The file was
    /// missing, the environment variables were not set, etc.
    Missing(Box<dyn std::error::Error + Send + Sync + 'static>),
    /// The provider was unable to parse the credentials in the configured location. The file
    /// structure was invalid, values were not UTF-8, etc.
    Invalid(Box<dyn std::error::Error + Send + Sync + 'static>),
    /// Any other error that might occur within the provider.
    Unknown(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl std::error::Error for Error {}
impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Error::Missing(e) => format!("missing: {e}"),
                Error::Invalid(e) => format!("invalid: {e}"),
                Error::Unknown(e) => format!("unknown: {e}"),
            }
        )
    }
}
