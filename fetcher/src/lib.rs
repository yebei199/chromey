pub use self::build_info::BuildInfo;
pub use self::error::FetcherError;
pub use self::fetcher::{BrowserFetcher, BrowserFetcherInstallation, BrowserFetcherOptions};
pub use self::host::BrowserHost;
pub use self::kind::BrowserKind;
pub use self::platform::Platform;
use self::runtime::Runtime;
pub use self::version::{BrowserVersion, Channel, Milestone, Revision, Version, VersionError};

/// Backward-compatible alias for [`BrowserFetcherInstallation`].
pub type BrowserFetcherRevisionInfo = BrowserFetcherInstallation;

/// Currently downloaded chromium revision (legacy).
///
/// Prefer using `BrowserKind::Chrome` with `Channel::Stable` for Chrome for Testing.
pub const CURRENT_REVISION: Revision = Revision::new(1355984);

mod build_info;
mod error;
mod fetcher;
mod host;
mod kind;
mod platform;
mod runtime;
mod version;
