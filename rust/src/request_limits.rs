//! Bounded request handling for the ledger routes: a per-request time limit, a concurrency limit, and a body size limit.
//!
//! A request holds a concurrency permit only while it runs. The time limit includes the wait for a permit and the time
//! spent reading the body, so a stalled client cannot hold a permit forever. Health and readiness routes are not limited,
//! so an operator can still see a loaded instance. Invalid settings stop startup: a limit that cannot be parsed is not
//! silently replaced by a default.

use std::time::Duration;

pub const ENV_TIMEOUT_SECS: &str = "AIGOV_REQUEST_TIMEOUT_SECS";
pub const ENV_MAX_CONCURRENT: &str = "AIGOV_MAX_CONCURRENT_REQUESTS";
pub const ENV_MAX_BODY_BYTES: &str = "AIGOV_MAX_BODY_BYTES";

pub const DEFAULT_TIMEOUT_SECS: u64 = 30;
pub const DEFAULT_MAX_CONCURRENT: usize = 256;
pub const DEFAULT_MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

const TIMEOUT_RANGE: (u64, u64) = (1, 600);
const CONCURRENT_RANGE: (usize, usize) = (1, 10_000);
const BODY_RANGE: (usize, usize) = (1024, 64 * 1024 * 1024);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestLimits {
    pub timeout: Duration,
    pub max_concurrent: usize,
    pub max_body_bytes: usize,
}

impl Default for RequestLimits {
    fn default() -> Self {
        RequestLimits {
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            max_concurrent: DEFAULT_MAX_CONCURRENT,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        }
    }
}

impl RequestLimits {
    /// Read the limits from the environment. An unset variable takes its default; a set variable must parse and be in range.
    pub fn from_env() -> Result<Self, String> {
        Self::parse(
            std::env::var(ENV_TIMEOUT_SECS).ok().as_deref(),
            std::env::var(ENV_MAX_CONCURRENT).ok().as_deref(),
            std::env::var(ENV_MAX_BODY_BYTES).ok().as_deref(),
        )
    }

    /// Pure parser, for tests. `None` means the variable is not set.
    pub fn parse(timeout: Option<&str>, max_concurrent: Option<&str>, max_body: Option<&str>) -> Result<Self, String> {
        let timeout_secs = match timeout {
            None => DEFAULT_TIMEOUT_SECS,
            Some(raw) => bounded(raw, ENV_TIMEOUT_SECS, TIMEOUT_RANGE)?,
        };
        let max_concurrent = match max_concurrent {
            None => DEFAULT_MAX_CONCURRENT,
            Some(raw) => bounded(raw, ENV_MAX_CONCURRENT, CONCURRENT_RANGE)?,
        };
        let max_body_bytes = match max_body {
            None => DEFAULT_MAX_BODY_BYTES,
            Some(raw) => bounded(raw, ENV_MAX_BODY_BYTES, BODY_RANGE)?,
        };
        Ok(RequestLimits {
            timeout: Duration::from_secs(timeout_secs),
            max_concurrent,
            max_body_bytes,
        })
    }
}

fn bounded<T>(raw: &str, name: &str, range: (T, T)) -> Result<T, String>
where
    T: std::str::FromStr + PartialOrd + Copy + std::fmt::Display,
{
    let value: T = raw
        .trim()
        .parse()
        .map_err(|_| format!("Invalid configuration: {name} must be an integer, got {raw:?}"))?;
    if value < range.0 || value > range.1 {
        return Err(format!(
            "Invalid configuration: {name} must be between {} and {}, got {value}",
            range.0, range.1
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_takes_the_defaults() {
        assert_eq!(RequestLimits::parse(None, None, None).unwrap(), RequestLimits::default());
    }

    #[test]
    fn valid_values_are_read() {
        let l = RequestLimits::parse(Some("5"), Some("16"), Some("65536")).unwrap();
        assert_eq!(l.timeout, Duration::from_secs(5));
        assert_eq!(l.max_concurrent, 16);
        assert_eq!(l.max_body_bytes, 65536);
    }

    #[test]
    fn out_of_range_and_unparseable_values_refuse_startup() {
        assert!(RequestLimits::parse(Some("0"), None, None).unwrap_err().contains(ENV_TIMEOUT_SECS));
        assert!(RequestLimits::parse(Some("601"), None, None).is_err());
        assert!(RequestLimits::parse(None, Some("0"), None).is_err());
        assert!(RequestLimits::parse(None, None, Some("1023")).is_err());
        assert!(RequestLimits::parse(None, Some("many"), None).unwrap_err().contains("must be an integer"));
        assert!(RequestLimits::parse(None, None, Some("-1")).is_err());
    }
}
