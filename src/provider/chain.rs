/*!
The chain provider composes other providers, executes them in order, and returns the first set
of credentials found.
*/

use std::fmt::Debug;

use crate::provider::{Error, Provider};
use crate::signature::Key;

/// Attempt to load credentials from different providers in order.
#[derive(Debug)]
pub struct Chain {
    providers: Vec<Box<dyn Provider>>,
}

impl Provider for Chain {
    fn credentials(&self) -> Result<Key, Error> {
        for provider in &self.providers {
            if let Ok(key) = provider.credentials() {
                return Ok(key);
            }
        }

        Err(Error::Missing(
            "no configured providers returned credentials".into(),
        ))
    }
}

/// Allows creating a [Chain] provider with a custom set of providers.
#[derive(Debug, Default)]
pub struct Builder {
    providers: Vec<Box<dyn Provider>>,
}

impl Builder {
    /// Create a new builder with the default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a new provider to the chain.
    pub fn add_provider(mut self, provider: impl Provider + 'static) -> Self {
        self.providers.push(Box::new(provider));

        self
    }

    /// Finalize the provider.
    pub fn build(self) -> Chain {
        Chain {
            providers: self.providers,
        }
    }
}
