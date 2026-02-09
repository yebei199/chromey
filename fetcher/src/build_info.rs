use std::fmt;

use crate::Revision;

/// Information about a build of a browser.
#[derive(Debug, Clone)]
pub struct BuildInfo {
    /// The revision of the browser (only set for Chromium or when resolved from a Channel).
    pub revision: Option<Revision>,
    /// The version of the browser (only set for Chrome for Testing).
    pub version: Option<String>,
    /// Unique identifier for the build (either the revision number or the version string).
    pub id: String,
}

impl fmt::Display for BuildInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ID: {}", self.id)?;
        if let Some(revision) = &self.revision {
            write!(f, ", Revision: {}", revision)?;
        }
        if let Some(version) = &self.version {
            write!(f, ", Version: {}", version)?;
        }
        Ok(())
    }
}

impl BuildInfo {
    #[doc(hidden)] // internal API
    pub fn revision(revision: Revision) -> Self {
        Self {
            id: revision.to_string(),
            revision: Some(revision),
            version: None,
        }
    }

    #[doc(hidden)] // internal API
    pub fn version(version: String) -> Self {
        Self {
            id: version.clone(),
            revision: None,
            version: Some(version),
        }
    }

    #[doc(hidden)] // internal API
    pub fn both(version: String, revision: Revision) -> Self {
        Self {
            id: version.clone(),
            revision: Some(revision),
            version: Some(version),
        }
    }
}
