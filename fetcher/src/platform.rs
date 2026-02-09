use std::fmt;

use crate::BuildInfo;

/// List of platforms with pre-built browser binaries.
#[derive(Clone, Copy, Debug)]
pub enum Platform {
    Linux,
    Mac,
    MacArm,
    Win32,
    Win64,
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Linux => "linux-x64",
                Self::Mac => "macos-x64",
                Self::MacArm => "macos-aarch64",
                Self::Win32 => "windows-x86",
                Self::Win64 => "windows-x64",
            }
        )
    }
}

impl Platform {
    /// List of all platforms.
    pub fn all() -> &'static [Platform] {
        &[
            Self::Linux,
            Self::Mac,
            Self::MacArm,
            Self::Win32,
            Self::Win64,
        ]
    }

    pub(crate) fn folder_name(&self, build_info: &BuildInfo) -> String {
        let platform = match self {
            Self::Linux => "linux",
            Self::Mac => "mac",
            Self::MacArm => "mac_arm",
            Self::Win32 => "win32",
            Self::Win64 => "win64",
        };
        format!("{platform}-{build_id}", build_id = build_info.id)
    }

    pub(crate) fn current() -> Option<Platform> {
        // Currently there are no builds for Linux arm
        if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            Some(Self::Linux)
        } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
            Some(Self::Mac)
        } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
            Some(Self::MacArm)
        } else if cfg!(all(target_os = "windows", target_arch = "x86")) {
            Some(Self::Win32)
        } else if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
            Some(Self::Win64)
        } else if cfg!(all(target_os = "windows", target_arch = "aarch64")) {
            // x64 emulation is available for windows 11
            if let os_info::Version::Semantic(major, _, _) = os_info::get().version() {
                if *major > 10 {
                    return Some(Self::Win64);
                }
            }
            None
        } else {
            None
        }
    }
}
