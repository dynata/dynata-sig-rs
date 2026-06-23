/*!
Types for working with time components
*/
use std::fmt;
use std::fmt::Display;
use std::str::FromStr;
use std::time::Duration;

use serde::de::{Error, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// An RFC-3339-formatted UTC timestamp.
#[derive(Debug, Clone)]
pub struct Timestamp(String, jiff::Timestamp);

impl Timestamp {
    /// Returns the current system time as a timestamp.
    pub fn now() -> Self {
        jiff::Timestamp::now().into()
    }

    /// Returns true if the supplied timestamp is strictly after self.
    ///
    /// # Examples
    ///
    /// ```
    /// use dynata_sig::time::Timestamp;
    /// use std::time::Duration;
    ///
    /// let before = Timestamp::now();
    /// let after = &before + Duration::from_secs(10);
    ///
    /// assert!(after.after(&before));
    /// ```
    pub fn after(&self, t: &Timestamp) -> bool {
        self.1 > t.1
    }

    /// Returns true if the current time is strictly after self.
    pub fn is_past(&self) -> bool {
        Timestamp::now().after(self)
    }

    /// Returns true if the supplied timestamp is strictly before self.
    ///
    /// # Examples
    ///
    /// ```
    /// use dynata_sig::time::Timestamp;
    /// use std::time::Duration;
    ///
    /// let after = Timestamp::now();
    /// let before = &after - Duration::from_secs(10);
    ///
    /// assert!(before.before(&after));
    /// ```
    pub fn before(&self, t: &Timestamp) -> bool {
        self.1 < t.1
    }

    /// Returns a [`Duration`] between self and now.
    pub fn until(&self) -> Duration {
        jiff::Timestamp::now()
            .until(self.1)
            .and_then(|span| span.try_into())
            .unwrap_or_else(|_| Duration::from_secs(0))
    }
}

impl Default for Timestamp {
    fn default() -> Self {
        Self::now()
    }
}

impl Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<jiff::Timestamp> for Timestamp {
    fn from(t: jiff::Timestamp) -> Self {
        Timestamp(t.to_string(), t)
    }
}

/// Indicates an error when parsing a timestamp
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ParseError;

impl std::error::Error for ParseError {}

impl Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid timestamp format")
    }
}

impl FromStr for Timestamp {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        jiff::Timestamp::from_str(s)
            .map_err(|_| ParseError)
            .map(|d| Timestamp(s.to_owned(), d))
    }
}

impl std::ops::Add<Duration> for &Timestamp {
    type Output = Timestamp;

    fn add(self, rhs: Duration) -> Self::Output {
        let n = self.1 + rhs;
        Timestamp(n.to_string(), n)
    }
}

impl std::ops::Add<Duration> for Timestamp {
    type Output = Timestamp;

    fn add(self, rhs: Duration) -> Self::Output {
        &self + rhs
    }
}

impl std::ops::Sub<Duration> for &Timestamp {
    type Output = Timestamp;

    fn sub(self, rhs: Duration) -> Self::Output {
        let n = self.1 - rhs;
        Timestamp(n.to_string(), n)
    }
}

impl std::ops::Sub<Duration> for Timestamp {
    type Output = Timestamp;

    fn sub(self, rhs: Duration) -> Self::Output {
        &self - rhs
    }
}

impl Serialize for Timestamp {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error>
    where
        D: Deserializer<'de>,
    {
        struct TimestampVisitor;

        impl<'de> Visitor<'de> for TimestampVisitor {
            type Value = Timestamp;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an RFC 3339 formatted timestamp")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                let dt: Timestamp = v
                    .parse()
                    .map_err(|_| E::custom(format!("invalid timestamp format: {v}")))?;
                Ok(dt)
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: Error,
            {
                let dt: Timestamp = v
                    .parse()
                    .map_err(|_| E::custom(format!("invalid timestamp format: {v}")))?;
                Ok(dt)
            }

            fn visit_newtype_struct<D>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, <D as Deserializer<'de>>::Error>
            where
                D: Deserializer<'de>,
            {
                deserializer.deserialize_any(self)
            }
        }
        deserializer.deserialize_newtype_struct("Timestamp", TimestampVisitor)
    }
}

impl From<Timestamp> for jiff::Timestamp {
    fn from(t: Timestamp) -> Self {
        t.1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn timestamp_after() {
        let n = Timestamp::now();
        let x = &n + Duration::from_secs(300);
        assert!(x.after(&n));
    }

    #[test]
    fn timestamp_not_after() {
        let n = Timestamp::now();
        let x = &n + Duration::from_secs(300);
        assert!(!n.after(&x));
    }

    #[test]
    fn timestamp_before() {
        let now = Timestamp::now();
        let subject = &now - Duration::from_secs(10);
        assert!(subject.before(&now));
    }

    #[test]
    fn timestamp_not_before() {
        let now = Timestamp::now();
        let subject = &now + Duration::from_secs(10);
        assert!(!subject.before(&now))
    }

    #[test]
    fn timestamp_until() {
        let n = Timestamp::now() + Duration::from_millis(5);
        sleep(Duration::from_millis(6));
        assert_eq!(Duration::from_millis(0), n.until());
    }

    #[test]
    fn parse_timestamp() {
        let s = "2021-03-30T14:17:29.208Z";
        let t: Timestamp = s.parse().unwrap();
        assert_eq!(s, t.to_string())
    }

    #[test]
    fn timestamp_precision_error() {
        let s = "2021-03-30T14:17:29.208832+09:38";
        let r: Result<Timestamp, ParseError> = s.parse();
        assert_eq!(
            Ok("2021-03-30T14:17:29.208832+09:38".to_owned()),
            r.map(|t| t.to_string())
        )
    }

    #[test]
    fn timestamp_format_error() {
        let s = "2021-03-30T14:17:29.208";
        let r: Result<Timestamp, ParseError> = s.parse();
        assert_eq!(ParseError, r.err().unwrap())
    }

    #[test]
    fn until() {
        let n: Timestamp = Timestamp::now() + Duration::from_secs(60);
        let d = n.until();
        assert!((Duration::from_secs(0) < d) && (d < Duration::from_secs(60)));
    }
}
