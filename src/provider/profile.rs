/*!
The profile provider can read credentials from a config file.

The default config file location is `~/.dynata/credentials`, and the default profile name is
`default`.
*/
use std::collections::HashMap;
use std::env::home_dir;
use std::path::PathBuf;

use ini::Ini;

use crate::provider::{Error, Provider};
use crate::signature::Key;

/// The default credentials config file location, relative to the current home directory.
pub const DEFAULT_CREDENTIALS_FILE: &str = ".dynata/credentials";
/// The default profile name.
pub const DEFAULT_PROFILE: &str = "default";

/// Load credentials from a named profile in a config file.
#[derive(Debug, Clone)]
pub struct Profile {
    file: PathBuf,
    profile: String,
}

impl Default for Profile {
    fn default() -> Self {
        Builder::new().build()
    }
}

impl Provider for Profile {
    fn credentials(&self) -> Result<Key, Error> {
        let file = Ini::load_from_file(&self.file)?;

        file.iter()
            .filter(|(name, _)| name.is_some())
            .map(|(section, properties)| {
                (
                    section.unwrap_or_default().to_string(),
                    (|| {
                        Ok(Key::new(
                            properties
                                .get("dynata_access_key")
                                .ok_or(Error::Invalid("profile missing access key".into()))?
                                .to_owned(),
                            properties
                                .get("dynata_secret_key")
                                .ok_or(Error::Invalid("profile missing secret key".into()))?
                                .to_owned(),
                        ))
                    })(),
                )
            })
            .collect::<HashMap<String, Result<Key, Error>>>()
            .remove(&self.profile)
            .ok_or(Error::Missing("no such profile".into()))?
    }
}

impl From<ini::Error> for Error {
    fn from(err: ini::Error) -> Self {
        Self::Unknown(err.into())
    }
}

/// Allows creating a [Profile] provider with optional config file and profile name overrides.
#[derive(Debug, Default)]
pub struct Builder {
    file: Option<PathBuf>,
    profile: Option<String>,
}

impl Builder {
    /// Create a new builder with the default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the optional config file override.
    pub fn file(mut self, file: impl Into<PathBuf>) -> Self {
        self.file = Some(file.into());

        self
    }

    /// Set the optional profile name override.
    pub fn profile(mut self, profile: String) -> Self {
        self.profile = Some(profile);

        self
    }

    /// Finalize the provider.
    pub fn build(self) -> Profile {
        Profile {
            file: self.file.unwrap_or_else(|| {
                let mut path = home_dir().unwrap_or_default();
                path.push(DEFAULT_CREDENTIALS_FILE);
                path
            }),
            profile: self.profile.unwrap_or(DEFAULT_PROFILE.into()),
        }
    }
}
