//! U8 — after uninstall, nothing remains that can install or launch.
//!
//! An updater that survives its own uninstall is a persistence mechanism. The
//! user asked for the program to be gone; an updater that is still installed
//! can still write files, still has a channel, and still talks to whatever
//! endpoint it was configured against. That is the whole of U8.
//!
//! The load-bearing constraint is the last one in the spec: **files outside the
//! declared install root are left alone.** An installer that wrote outside its
//! own root cannot clean up after itself, and an uninstaller that deleted
//! outside that root to compensate would destroy user data — a browser
//! profile in the same directory, a document the user edited in place. So the
//! residue check fails closed on anything outside the root rather than
//! reporting it as "uninstalled with warnings".
//!
//! The model here is deliberately in-memory and takes an injected clock, like
//! the rest of `update_path`. What matters is which paths are claimed, who
//! owns them, and whether an answer can be wrong — and a test can only
//! exercise a wrong answer by supplying one.

use core::fmt;

/// U8's refusal, with the rule each variant enforces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UninstallError {
    /// No install root was declared, so nothing can be proven to be app-owned.
    ///
    /// Fail-closed: without a root, every path is outside it, and an
    /// uninstaller that proceeded would either delete nothing or delete
    /// something it should not.
    NoInstallRoot,
    InstallRootTooLong {
        length: usize,
        maximum: usize,
    },
    /// A path claimed for removal does not lie under the declared root.
    OutsideInstallRoot {
        path: String,
    },
    /// A path is a bare filesystem root, or contains a traversal.
    PathNotContained {
        path: String,
    },
    /// Something that can install or launch survived.
    ResidueRemains {
        kind: ResidueKind,
        detail: String,
    },
    /// The removal plan targets a file the user is understood to own.
    UserDataRefused {
        path: String,
    },
}

/// What kind of thing survived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResidueKind {
    /// The scheduled task or service that polls for updates.
    UpdateScheduler,
    /// An autostart entry for the application or the updater.
    AutostartEntry,
    /// A credential, token, or cached entitlement.
    CachedSecret,
    /// The application or updater binary itself.
    InstalledBinary,
}

impl ResidueKind {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::UpdateScheduler => "update_scheduler",
            Self::AutostartEntry => "autostart_entry",
            Self::CachedSecret => "cached_secret",
            Self::InstalledBinary => "installed_binary",
        }
    }

    /// Whether something of this kind lets the product still act after uninstall.
    ///
    /// U8 asks a single question — *can anything still install or launch?* —
    /// and every [`ResidueKind`] currently answers yes. That is not an
    /// accident to be papered over with a four-variant enumeration here: the
    /// enumeration would make adding a fifth kind silently mean "safe", which
    /// is the wrong default for the question being asked. The match is
    /// exhaustive with no wildcard, so a new variant is a compile error here
    /// until someone decides which way it answers.
    #[must_use]
    pub const fn is_persistence(self) -> bool {
        match self {
            Self::UpdateScheduler
            | Self::AutostartEntry
            | Self::CachedSecret
            | Self::InstalledBinary => true,
        }
    }
}

/// The longest install root accepted.
pub const MAX_INSTALL_ROOT_BYTES: usize = 512;

/// Something the product installed, and whether the user owns it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedPath {
    path: String,
    kind: ResidueKind,
    /// Set when the path holds user data rather than product files.
    ///
    /// A user-data path is reported, never removed. The uninstaller's job is
    /// to leave the user's documents alone, and a flag on a struct the caller
    /// populates is the only place that decision can be recorded.
    user_data: bool,
}

impl OwnedPath {
    /// A product-owned path the uninstaller may remove.
    #[must_use]
    pub fn product(path: &str, kind: ResidueKind) -> Self {
        Self {
            path: path.to_string(),
            kind,
            user_data: false,
        }
    }

    /// A path holding user data, which the uninstaller reports and keeps.
    ///
    /// Use for anything inside the install root the user could have written to.
    #[must_use]
    pub fn user_owned(path: &str, kind: ResidueKind) -> Self {
        Self {
            path: path.to_string(),
            kind,
            user_data: true,
        }
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub const fn kind(&self) -> ResidueKind {
        self.kind
    }

    #[must_use]
    pub const fn is_user_data(&self) -> bool {
        self.user_data
    }
}

/// Everything the product claims it installed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UninstallPlan {
    install_root: Option<String>,
    owned: Vec<OwnedPath>,
}

impl UninstallPlan {
    /// Declares where the product was installed.
    ///
    /// Required. U8 cannot be satisfied without it: every containment check
    /// needs a root to contain against, and a plan with no root is a plan that
    /// would have to guess.
    ///
    /// # Errors
    ///
    /// Returns `InstallRootTooLong` above [`MAX_INSTALL_ROOT_BYTES`], or
    /// `PathNotContained` if the root is a filesystem root or a bare drive
    /// letter, because "remove everything under `C:`" is not an uninstall
    /// plan.
    pub fn declare_root(&mut self, install_root: &str) -> Result<(), UninstallError> {
        if install_root.trim().is_empty() {
            return Err(UninstallError::NoInstallRoot);
        }
        if install_root.len() > MAX_INSTALL_ROOT_BYTES {
            return Err(UninstallError::InstallRootTooLong {
                length: install_root.len(),
                maximum: MAX_INSTALL_ROOT_BYTES,
            });
        }
        let trimmed = install_root.trim_end_matches('/');
        if !is_plausible_root(trimmed) {
            // Reported verbatim rather than trimmed, because the string the
            // caller passed is the one they can recognise in their own logs.
            return Err(UninstallError::PathNotContained {
                path: install_root.to_string(),
            });
        }
        // Normalized too, so the root and every recorded path are compared in
        // one normal form. Leaving the root raw while paths are normalized
        // makes a correct path look outside its own root.
        self.install_root = Some(normalize(trimmed));
        Ok(())
    }

    /// Records a path the product installed.
    ///
    /// Refuses anything outside the declared root at the point of recording,
    /// not at removal. An installer that wrote outside its own root is a
    /// design bug, and catching it at the moment it is introduced names the
    /// bug instead of leaving it to surface during an uninstall.
    ///
    /// # Errors
    ///
    /// Returns `NoInstallRoot` if no root was declared, `PathNotContained` for
    /// a traversing or root-shaped path, and `OutsideInstallRoot` for a path
    /// that resolves outside the declared root.
    pub fn record(&mut self, owned: OwnedPath) -> Result<(), UninstallError> {
        let root = self
            .install_root
            .as_ref()
            .ok_or(UninstallError::NoInstallRoot)?;
        let normalized = normalize(owned.path());
        if normalized.split('/').any(|segment| segment == "..") {
            return Err(UninstallError::PathNotContained {
                path: owned.path().to_string(),
            });
        }
        if !is_under(root, &normalized) {
            return Err(UninstallError::OutsideInstallRoot {
                path: owned.path().to_string(),
            });
        }
        self.owned.push(owned);
        Ok(())
    }

    #[must_use]
    pub fn install_root(&self) -> Option<&str> {
        self.install_root.as_deref()
    }

    /// The paths an uninstall would remove.
    ///
    /// User data is excluded. It is reported by [`Self::retained_user_data`]
    /// instead.
    #[must_use]
    pub fn removal_targets(&self) -> Vec<&str> {
        self.owned
            .iter()
            .filter(|entry| !entry.is_user_data())
            .map(OwnedPath::path)
            .collect()
    }

    /// The paths the uninstall deliberately leaves alone.
    #[must_use]
    pub fn retained_user_data(&self) -> Vec<&str> {
        self.owned
            .iter()
            .filter(|entry| entry.is_user_data())
            .map(OwnedPath::path)
            .collect()
    }

    /// Confirms that an uninstall leaves nothing able to install or launch.
    ///
    /// `surviving` is what the machine reports is still present afterwards.
    ///
    /// # Errors
    ///
    /// Returns [`UninstallError::ResidueRemains`] for the first surviving
    /// item. The check is fail-closed in the sense that matters: an empty
    /// `surviving` list is the only input that verifies, and a caller that has
    /// not actually enumerated the machine has passed an empty list.
    ///
    /// [`UninstallError::UserDataRefused`] is returned when a surviving entry
    /// is marked as user data, because "it survived" and "you were supposed to
    /// remove it" are different failures and conflating them hides the first
    /// behind the second.
    pub fn confirm_clean(&self, surviving: &[OwnedPath]) -> Result<(), UninstallError> {
        let Some(root) = self.install_root.as_ref() else {
            return Err(UninstallError::NoInstallRoot);
        };

        for entry in surviving {
            if entry.is_user_data() {
                return Err(UninstallError::UserDataRefused {
                    path: entry.path().to_string(),
                });
            }
            if !is_under(root, &normalize(entry.path())) {
                return Err(UninstallError::OutsideInstallRoot {
                    path: entry.path().to_string(),
                });
            }
        }

        // The load-bearing check: anything still present that can install or
        // launch is a failure, whatever it is called. Checking only the paths
        // this plan happened to record would miss a scheduler or autostart
        // entry the product created and then forgot about.
        if let Some(leftover) = surviving.iter().find(|entry| entry.kind().is_persistence()) {
            return Err(UninstallError::ResidueRemains {
                kind: leftover.kind(),
                detail: leftover.path().to_string(),
            });
        }

        Ok(())
    }
}

/// Collapses `.` segments and duplicate separators.
///
/// A leading `/` is kept, because `is_under` compares on segment boundaries and
/// a root of `/opt/kmj` would otherwise never contain its own children.
///
/// Does **not** resolve `..`. A `..` is left in place so the containment check
/// can see it and refuse, rather than having this function quietly resolve a
/// traversal into a path that looks contained.
fn normalize(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        parts.push(segment);
    }
    format!("/{}", parts.join("/"))
}

/// Whether `path` lies under `root`, on segment boundaries.
///
/// A string prefix is not containment: `/opt/kmj-evil` starts with
/// `/opt/kmj` but is a different directory, and treating it as inside the root
/// is exactly the mistake that makes an uninstaller delete a neighbour.
fn is_under(root: &str, path: &str) -> bool {
    if path == root {
        return true;
    }
    path.strip_prefix(root)
        .is_some_and(|rest| rest.starts_with('/'))
}

/// Whether a string could name an install root at all.
///
/// Takes the *trimmed* root, so `/` and `C:` are both already down to one or
/// two characters by the time they arrive. An earlier version also compared the
/// normalized form against `"/"`, and a mutation dropping that comparison
/// survived with every test green -- the length check refuses the same inputs.
/// Rather than keep a clause that cannot change an answer, it is gone.
fn is_plausible_root(root: &str) -> bool {
    // A drive letter (`C:`) or a filesystem root (`/`) is not an install root.
    if root.len() <= 2 {
        return false;
    }
    if root.split('/').any(|segment| segment == "..") {
        return false;
    }
    true
}

impl fmt::Display for UninstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoInstallRoot => write!(
                f,
                "U8: no install root declared, so no path can be proven app-owned"
            ),
            Self::InstallRootTooLong { length, maximum } => write!(
                f,
                "U8: install root is {length} bytes, over the {maximum} limit"
            ),
            Self::OutsideInstallRoot { path } => {
                write!(f, "U8: {path:?} is outside the declared install root")
            }
            Self::PathNotContained { path } => {
                write!(f, "U8: {path:?} is a root or a traversing path")
            }
            Self::ResidueRemains { kind, detail } => write!(
                f,
                "U8: {} still present after uninstall: {detail}",
                kind.name()
            ),
            Self::UserDataRefused { path } => {
                write!(
                    f,
                    "U8: {path:?} was supposed to be removed but is user data"
                )
            }
        }
    }
}

impl std::error::Error for UninstallError {}

#[cfg(test)]
#[path = "uninstall_tests.rs"]
mod tests;
