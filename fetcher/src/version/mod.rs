use std::str::FromStr;

pub use self::channel::Channel;
use self::error::Result;
pub use self::error::VersionError;
pub use self::milestone::Milestone;
pub use self::revision::Revision;
pub use self::version::Version;
use crate::{BrowserHost, BrowserKind, BuildInfo, Platform};

mod channel;
mod error;
pub(crate) mod metadata;
mod milestone;
mod revision;
#[allow(clippy::module_inception)]
mod version;

/// Represents a version of a browser.
///
/// The version can be a channel, a revision, a version string, or a milestone.
/// Not all combinations are valid for all browser kinds.
///
/// - **Chrome/ChromeHeadlessShell**: Use `Channel`, `Version`, or `Milestone`.
///   Defaults to `Channel(Stable)` to always fetch the latest stable version.
/// - **Chromium**: Use `Revision` or `Channel(Canary)`.
///   Defaults to a known-good revision.
#[derive(Clone, Copy, Debug)]
pub enum BrowserVersion {
    Channel(Channel),
    Revision(Revision),
    Version(Version),
    Milestone(Milestone),
}

impl BrowserVersion {
    #[doc(hidden)] // internal API
    pub fn current(kind: BrowserKind) -> Self {
        match kind {
            BrowserKind::Chromium => Self::Revision(Revision::new(1355984)),
            BrowserKind::Chrome => Self::Channel(Channel::Stable),
            BrowserKind::ChromeHeadlessShell => Self::Channel(Channel::Stable),
        }
    }

    pub(crate) async fn resolve(
        &self,
        kind: BrowserKind,
        platform: Platform,
        host: &BrowserHost,
    ) -> Result<BuildInfo> {
        match self {
            Self::Revision(revision) => revision.resolve(kind, host).await,
            Self::Channel(channel) => channel.resolve(kind, platform, host).await,
            Self::Version(version) => version.resolve(kind, host).await,
            Self::Milestone(milestone) => milestone.resolve(kind, host).await,
        }
    }
}

impl FromStr for BrowserVersion {
    type Err = VersionError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if let Ok(channel) = s.parse::<Channel>() {
            return Ok(Self::Channel(channel));
        }

        if let Ok(version) = s.parse::<Version>() {
            return Ok(Self::Version(version));
        }

        if let Ok(revision) = s.parse::<Revision>() {
            return Ok(Self::Revision(revision));
        }

        Err(VersionError::InvalidVersion(s.to_string()))
    }
}

impl TryFrom<String> for BrowserVersion {
    type Error = VersionError;

    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        value.parse()
    }
}
