use std::{fmt, str::FromStr};

use super::{Result, VersionError};
use crate::{BrowserHost, BrowserKind, BuildInfo};

/// A [`Revision`] represents a chromium snapshot revision number.
///
/// Revisions are only valid for the legacy `Chromium` browser kind
/// (chromium-browser-snapshots bucket).
#[derive(Clone, Copy, Debug, PartialOrd, Ord, PartialEq, Eq)]
pub struct Revision(u32);

impl Revision {
    pub const fn new(revision: u32) -> Self {
        Self(revision)
    }

    pub(crate) async fn resolve(
        &self,
        kind: BrowserKind,
        _host: &BrowserHost,
    ) -> Result<BuildInfo> {
        match kind {
            BrowserKind::Chromium => Ok(BuildInfo::revision(*self)),
            _ => Err(VersionError::ResolveFailed(anyhow::anyhow!(
                "Revision-based lookup is only supported for Chromium, use Version or Channel for Chrome/ChromeHeadlessShell"
            ))),
        }
    }
}

impl From<u32> for Revision {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<Revision> for u32 {
    fn from(value: Revision) -> Self {
        value.0
    }
}

impl FromStr for Revision {
    type Err = VersionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let revision = s
            .parse::<u32>()
            .map_err(|_| VersionError::InvalidRevision(s.to_string()))?;
        Ok(Revision(revision))
    }
}

impl TryFrom<String> for Revision {
    type Error = VersionError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl fmt::Display for Revision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
