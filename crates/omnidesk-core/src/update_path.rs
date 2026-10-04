//! The update path for M12's `safe_update_path`.
//!
//! [`UPDATE_INTEGRITY.md`](../../docs/UPDATE_INTEGRITY.md) specifies U1-U9. This
//! module is the part of that design that can be built and refuted without a
//! running installer, a signing service, or a network.
//!
//! # The property that matters
//!
//! Update handling fails in the wrong order constantly, and it fails that way
//! invisibly: a client that hashes the artifact after extracting it has already
//! run an attacker's parser. So this API is shaped as a chain of borrowed
//! types, where each step borrows the previous step's output:
//!
//! ```text
//! TrustAnchor -> VerifiedArtifact -> VerifiedManifest -> StagedUpdate -> InstallPlan
//! ```
//!
//! There is no way to name an `InstallPlan` without having produced a
//! `VerifiedArtifact`, and no way to produce a `VerifiedArtifact` without
//! having verified a signature against a compiled-in key. Skipping a check is
//! not a branch that can be flipped; it is unrepresentable.
//!
//! # What is deliberately not here
//!
//! * **No extraction.** [`StagedUpdate`] holds a validated member list, not
//!   extracted files. Doing the real extraction needs an archive parser, and a
//!   parser reachable before verification is exactly what U1 forbids. The
//!   traversal check (U7) runs over member *names*, which is where it has to
//!   run regardless.
//!
//! * **No signature algorithm choice.** [`TrustAnchor`] wraps
//!   `ed25519-dalek::VerifyingKey` because that crate is already a dependency
//!   and is a sound implementation. Picking the shipping algorithm is a
//!   decision with its own review; this does not make it.
//!
//! * **No configuration.** U6 forbids a switch that lowers verification, so
//!   nothing here is constructed from config, environment, or CLI. A verifier
//!   assembled from external input is a verifier an attacker can assemble
//!   differently.

use core::fmt;

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::log_scrubber::{PeerSummary, SafeRecord, SafeRecordBuilder};

/// Maps a validated channel to a `&'static str` for a log record.
///
/// Returns `"other"` rather than the caller's string because `SafeValue::State`
/// takes `&'static str`, and the alternative -- `String::leak` -- would hand
/// every staged update a permanent allocation to hold a value that is one of
/// two known constants. Both checks in `StagedUpdate::stage` compare against
/// these constants, so anything else reaching here is not a channel.
fn channel_label(channel: &str) -> &'static str {
    match channel {
        "stable" => "stable",
        "beta" => "beta",
        _ => "other",
    }
}

/// Maps a validated platform to a `&'static str`. See [`channel_label`].
fn platform_label(platform: &str) -> &'static str {
    match platform {
        "windows-x86_64" => "windows-x86_64",
        "windows-aarch64" => "windows-aarch64",
        "macos-x86_64" => "macos-x86_64",
        "macos-aarch64" => "macos-aarch64",
        "linux-x86_64" => "linux-x86_64",
        "linux-aarch64" => "linux-aarch64",
        _ => "other",
    }
}

/// The longest install-root prefix this module will accept, in bytes.
///
/// An install root that has grown past this is not a real path; it is a sign
/// that the value came from somewhere it should not have.
pub const MAX_INSTALL_ROOT_BYTES: usize = 512;

/// The longest archive member path this module will accept, in bytes.
pub const MAX_MEMBER_PATH_BYTES: usize = 256;

/// A compiled-in public key that update signatures are checked against.
///
/// U2: the anchor is a value baked into the shipped binary. It is not
/// `Deserialize`, not read from disk, and there is no setter. Rotation means a
/// new build carrying [`TrustAnchorSet`].
#[derive(Clone)]
pub struct TrustAnchor {
    key: VerifyingKey,
    /// Human-readable key id, for records. Never the key material.
    key_id: &'static str,
}

impl TrustAnchor {
    /// Wraps a signing key to obtain the public anchor.
    ///
    /// Takes `&SigningKey` rather than a `VerifyingKey` because a caller that
    /// holds only a public key cannot accidentally retain the private half in
    /// this type.
    #[must_use]
    pub fn from_signing_key(key: &SigningKey, key_id: &'static str) -> Self {
        Self {
            key: key.verifying_key(),
            key_id,
        }
    }

    /// The key identifier, safe to record.
    #[must_use]
    pub const fn key_id(&self) -> &'static str {
        self.key_id
    }

    /// Verifies a detached signature over `payload`.
    ///
    /// U1. Any failure is terminal: this returns `Result`, and every caller
    /// in this module propagates rather than falling back.
    ///
    /// # Errors
    ///
    /// Returns `SignatureInvalid` naming the key that was tried. There is no
    /// partial success to recover from.
    pub fn verify(&self, payload: &[u8], signature: &Signature) -> Result<(), UpdateError> {
        self.key
            .verify(payload, signature)
            .map_err(|_| UpdateError::SignatureInvalid {
                key_id: self.key_id,
            })
    }
}

impl fmt::Debug for TrustAnchor {
    /// Never prints key material, only the id.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustAnchor")
            .field("key_id", &self.key_id)
            .field("key", &"<redacted>")
            .finish()
    }
}

/// Two anchors, so a build can verify during a key rotation overlap window.
///
/// U2 accepts that out-of-band rotation needs a binary that already trusts the
/// new key. This type is how that overlap is expressed without any runtime
/// toggle: the second key is present in the binary or it is not.
#[derive(Clone, Debug)]
pub struct TrustAnchorSet {
    primary: TrustAnchor,
    rollover: Option<TrustAnchor>,
}

impl TrustAnchorSet {
    #[must_use]
    pub const fn new(primary: TrustAnchor, rollover: Option<TrustAnchor>) -> Self {
        Self { primary, rollover }
    }

    /// Number of anchors this build will accept.
    #[must_use]
    pub const fn len(&self) -> usize {
        if self.rollover.is_some() { 2 } else { 1 }
    }

    /// Whether no anchor at all is configured.
    ///
    /// A build compiled with no anchor cannot verify anything. That must be
    /// impossible to construct accidentally, so it is stated rather than
    /// inferred.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Returns the anchor that accepted `payload`, or `None`.
    ///
    /// Tries the primary first. Order is not a policy decision: both anchors
    /// are equally trusted, and an attacker choosing between them gains
    /// nothing, because either one is compiled in and was signed off at build
    /// time.
    #[must_use]
    pub fn verify(&self, payload: &[u8], signature: &Signature) -> Option<&'static str> {
        if self.primary.verify(payload, signature).is_ok() {
            return Some(self.primary.key_id);
        }
        if let Some(rollover) = &self.rollover {
            if rollover.verify(payload, signature).is_ok() {
                return Some(rollover.key_id);
            }
        }
        None
    }
}

/// A payload whose signature has been verified against a compiled-in anchor.
///
/// Unconstructible except by [`TrustAnchor::verify`], which is what makes U1
/// a type-level property rather than a code-review item.
#[derive(Clone, Debug)]
pub struct VerifiedArtifact {
    bytes: Vec<u8>,
    digest: [u8; 32],
    key_id: &'static str,
}

impl VerifiedArtifact {
    /// The SHA-256 of the verified bytes.
    ///
    /// U4: the manifest is checked against this, and the client checks the
    /// artifact against the manifest. Both comparisons happen before anything
    /// is written.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// The digest, lowercase hex, for comparison against manifest text.
    #[must_use]
    pub fn digest_hex(&self) -> String {
        hex(&self.digest)
    }

    /// The anchor that accepted this artifact.
    #[must_use]
    pub const fn key_id(&self) -> &'static str {
        self.key_id
    }

    /// The verified bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// One entry in a signed release manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestEntry {
    pub path: String,
    pub digest_hex: String,
    pub mode: u32,
}

/// A release manifest whose signature has been verified.
#[derive(Clone, Debug)]
pub struct VerifiedManifest {
    version: u32,
    channel: String,
    platform: String,
    minimum_client_version: u32,
    entries: Vec<ManifestEntry>,
    key_id: &'static str,
}

/// A manifest that is not yet verified.
///
/// Parsing produces this, not a `VerifiedManifest`: U1 requires that
/// verification happen in code that does not also parse, so parse and verify
/// are separate types and there is no borrowed path from untrusted bytes to a
/// verified manifest.
#[derive(Clone, Debug)]
pub struct UnverifiedManifest {
    raw: String,
}

impl UnverifiedManifest {
    /// Wraps manifest bytes received from a metadata server.
    ///
    /// U9: metadata is untrusted input regardless of transport. Nothing has
    /// checked this yet.
    #[must_use]
    pub const fn from_bytes(raw: String) -> Self {
        Self { raw }
    }

    /// Verifies the signature and parses the body.
    ///
    /// Parsing happens only after verification returns `Ok`, which is the
    /// ordering U1 requires.
    ///
    /// # Errors
    ///
    /// Returns `SignatureInvalid` if no compiled-in anchor accepted the
    /// signature, and `ManifestMalformed` if the body is not the shape this
    /// parser accepts. The signature is checked first, so an unparsable body
    /// from an unverified source reports `SignatureInvalid`.
    pub fn verify_and_parse(
        &self,
        anchors: &TrustAnchorSet,
        signature: &Signature,
    ) -> Result<VerifiedManifest, UpdateError> {
        let key_id = anchors.verify(self.raw.as_bytes(), signature).ok_or(
            UpdateError::SignatureInvalid {
                key_id: "<none-of-the-compiled-in-anchors>",
            },
        )?;

        let parsed = ManifestBody::parse(&self.raw)?;
        Ok(VerifiedManifest {
            version: parsed.version,
            channel: parsed.channel,
            platform: parsed.platform,
            minimum_client_version: parsed.minimum_client_version,
            entries: parsed.entries,
            key_id,
        })
    }
}

/// The manifest body, kept separate so `VerifiedManifest` holds only checked data.
struct ManifestBody {
    version: u32,
    channel: String,
    platform: String,
    minimum_client_version: u32,
    entries: Vec<ManifestEntry>,
}

impl ManifestBody {
    /// A deliberately small parser.
    ///
    /// It reads the fields U4 names and ignores anything else. A general JSON
    /// parser would accept nested objects, arrays, and escapes that no check
    /// looks at, and every one of those is an untested path through code that
    /// decides whether new code runs.
    fn parse(raw: &str) -> Result<Self, UpdateError> {
        let mut version = None;
        let mut channel = None;
        let mut platform = None;
        let mut minimum_client_version = None;
        let mut entries: Vec<ManifestEntry> = Vec::new();

        for field in split_fields(object_body(raw)?)? {
            match field.key {
                "version" => version = Some(parse_u32(field.value)?),
                "channel" => channel = Some(field.value.to_owned()),
                "platform" => platform = Some(field.value.to_owned()),
                "minimum_client_version" => minimum_client_version = Some(parse_u32(field.value)?),
                "entry" => entries.push(parse_entry(field.value)?),
                // Unknown keys are ignored rather than rejected. A manifest
                // produced by a *newer* release tool must still be readable by
                // an older client, or key rotation (U2) would require the client
                // to update before it could accept any signed manifest at all.
                _ => {}
            }
        }

        let version = version.ok_or(UpdateError::ManifestMalformed {
            detail: "no version",
        })?;
        let channel = channel.ok_or(UpdateError::ManifestMalformed {
            detail: "no channel",
        })?;
        let platform = platform.ok_or(UpdateError::ManifestMalformed {
            detail: "no platform",
        })?;
        let minimum_client_version =
            minimum_client_version.ok_or(UpdateError::ManifestMalformed {
                detail: "no minimum_client_version",
            })?;

        if version == 0 || minimum_client_version == 0 {
            return Err(UpdateError::ManifestMalformed {
                detail: "version fields must be greater than zero",
            });
        }

        Ok(Self {
            version,
            channel,
            platform,
            minimum_client_version,
            entries,
        })
    }
}

/// A `key: value` pair taken from the manifest text.
struct Field<'a> {
    key: &'a str,
    value: &'a str,
}

/// The body of the manifest's single top-level object, i.e. `raw` minus its
/// outermost braces.
fn object_body(raw: &str) -> Result<&str, UpdateError> {
    raw.trim()
        .strip_prefix('{')
        .and_then(|rest| rest.strip_suffix('}'))
        .ok_or(UpdateError::ManifestMalformed {
            detail: "not a single top-level object",
        })
}

/// Splits one object's body into its `key: value` fields.
///
/// Tracks brace depth and quoted spans, so a member whose value is itself an
/// object -- `"entry":{...}` -- is returned whole rather than split at its first
/// `}`. Without this, the fields *inside* that object come back looking like
/// top-level fields. The unknown-field test exists because of that, and it
/// failed against the first version of this function.
///
/// A member's key runs from just after the previous `{`, `}`, or `,` to its
/// colon. That boundary is tracked forward rather than found by scanning
/// backwards over the key text, because a backwards scan cannot tell where the
/// key ends -- which is why the first version produced empty keys.
fn split_fields(body: &str) -> Result<Vec<Field<'_>>, UpdateError> {
    let mut fields = Vec::new();
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut pending: Option<(usize, usize)> = None; // (key_start, colon_index)
    let mut object_start: Option<usize> = None;
    let mut member_start: Option<usize> = Some(0);

    for (index, ch) in body.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_string => escaped = true,
            '"' => in_string = !in_string,
            '{' => {
                depth += 1;
                // An object-valued member: its content runs to the matching `}`.
                if depth == 1 && pending.is_some() {
                    fields.push(Field {
                        key: take_key(body, pending.take()),
                        value: "",
                    });
                    object_start = Some(index + 1);
                    member_start = None;
                }
            }
            '}' => {
                depth = depth.checked_sub(1).ok_or(UpdateError::ManifestMalformed {
                    detail: "closing brace before opening brace",
                })?;
                if depth == 0 {
                    if let Some(start) = object_start.take() {
                        if let Some(last) = fields.last_mut() {
                            last.value = &body[start..index];
                        }
                    }
                    member_start = Some(index + 1);
                }
            }
            ':' if !in_string && depth == 0 && pending.is_none() => {
                pending = Some((member_start.unwrap_or(index), index));
            }
            ',' if !in_string && depth == 0 => {
                if let Some((key_start, colon)) = pending.take() {
                    fields.push(Field {
                        key: unquote(&body[key_start..colon]),
                        value: unquote(&body[colon + 1..index]),
                    });
                }
                member_start = Some(index + 1);
            }
            _ => {}
        }
    }

    if depth != 0 {
        return Err(UpdateError::ManifestMalformed {
            detail: "unbalanced braces",
        });
    }
    // A trailing scalar member has no comma after it.
    if let Some((key_start, colon)) = pending.take() {
        fields.push(Field {
            key: unquote(&body[key_start..colon]),
            value: unquote(&body[colon + 1..]),
        });
    }
    Ok(fields)
}

fn take_key(raw: &str, pending: Option<(usize, usize)>) -> &str {
    match pending {
        Some((key_start, colon)) => unquote(&raw[key_start..colon]),
        None => "",
    }
}

fn unquote(raw: &str) -> &str {
    raw.trim().trim_matches('"')
}

fn parse_u32(value: &str) -> Result<u32, UpdateError> {
    if value.len() > 10 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(UpdateError::ManifestMalformed {
            detail: "version is not a plain non-negative integer",
        });
    }
    value
        .parse::<u32>()
        .map_err(|_| UpdateError::ManifestMalformed {
            detail: "version does not fit in 32 bits",
        })
}

fn parse_entry(value: &str) -> Result<ManifestEntry, UpdateError> {
    let mut path = None;
    let mut digest_hex = None;
    let mut mode = None;

    for field in split_fields(value)? {
        match field.key {
            "path" => path = Some(field.value.to_owned()),
            "digest" => digest_hex = Some(field.value.to_owned()),
            "mode" => {
                // Both spellings are accepted: `0o755` is what the manifest
                // writer emits, a bare number is what a hand-edit produces.
                let parsed = field.value.strip_prefix("0o").map_or_else(
                    || parse_u32(field.value).ok(),
                    |octal| u32::from_str_radix(octal, 8).ok(),
                );
                mode = Some(parsed.ok_or(UpdateError::ManifestMalformed {
                    detail: "mode is not a number",
                })?);
            }
            _ => {}
        }
    }

    Ok(ManifestEntry {
        path: path.ok_or(UpdateError::ManifestMalformed {
            detail: "entry without a path",
        })?,
        digest_hex: digest_hex.ok_or(UpdateError::ManifestMalformed {
            detail: "entry without a digest",
        })?,
        mode: mode.ok_or(UpdateError::ManifestMalformed {
            detail: "entry without a mode",
        })?,
    })
}

/// A member of a verified archive, validated against the install root.
///
/// U7. The check runs on the *name*, before anything is extracted, and
/// rejection is structural: no sanitising, no stripping, no warning. An archive
/// containing `../` is an archive the update path refuses to touch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveMember {
    path: String,
    mode: u32,
    is_executable: bool,
}

impl ArchiveMember {
    /// Validates one archive member name.
    ///
    /// Rejects, in order: empty names, absolute paths, drive-letter paths, UNC
    /// paths, any `.` or `..` component, backslashes used as separators, names
    /// over the length limit, and control characters.
    ///
    /// # Errors
    ///
    /// Returns `UnsafeMemberPath` naming the reason. Rejection is total: there
    /// is no sanitised form of a refused name.
    pub fn validate(name: &str, mode: u32) -> Result<Self, UpdateError> {
        if name.is_empty() {
            return Err(UpdateError::UnsafeMemberPath {
                path: "<empty>".to_owned(),
                reason: "empty path",
            });
        }
        if name.len() > MAX_MEMBER_PATH_BYTES {
            return Err(UpdateError::UnsafeMemberPath {
                path: truncate_for_report(name),
                reason: "path exceeds the member length limit",
            });
        }
        if name.chars().any(char::is_control) {
            return Err(UpdateError::UnsafeMemberPath {
                path: truncate_for_report(name),
                reason: "path contains a control character",
            });
        }
        if name.contains('\\') {
            // A backslash is legal in a Windows *file* name but is a
            // separator here. Accepting it would mean two different separators
            // for one grammar, which is how traversal checks get bypassed.
            return Err(UpdateError::UnsafeMemberPath {
                path: truncate_for_report(name),
                reason: "backslash used as a path separator",
            });
        }
        if name.starts_with('/') {
            return Err(UpdateError::UnsafeMemberPath {
                path: truncate_for_report(name),
                reason: "absolute path",
            });
        }
        if has_drive_letter(name) {
            return Err(UpdateError::UnsafeMemberPath {
                path: truncate_for_report(name),
                reason: "drive-letter absolute path",
            });
        }
        for component in name.split('/') {
            if component.is_empty() {
                return Err(UpdateError::UnsafeMemberPath {
                    path: truncate_for_report(name),
                    reason: "empty path component",
                });
            }
            if component == "." || component == ".." {
                return Err(UpdateError::UnsafeMemberPath {
                    path: truncate_for_report(name),
                    reason: "dot path component",
                });
            }
        }

        Ok(Self {
            path: name.to_owned(),
            mode,
            // U7's companion: a manifest cannot grant execute permission to a
            // file the manifest did not list as an executable. Anything with
            // any execute bit set is treated as executable, so there is no
            // umask-dependent ambiguity about which bit "counts".
            is_executable: mode & 0o111 != 0,
        })
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub const fn mode(&self) -> u32 {
        self.mode
    }

    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.is_executable
    }

    /// Rejects a member that is executable but not declared as a program.
    ///
    /// An executable dropped where no executable belongs is how an archive
    /// turns a data directory into a launch point.
    ///
    /// # Errors
    ///
    /// Returns `UnexpectedExecutable` if the member has an execute bit and its
    /// path is not among `declared_programs`.
    pub fn reject_unexpected_executable(
        &self,
        declared_programs: &[&str],
    ) -> Result<(), UpdateError> {
        if self.is_executable && !declared_programs.contains(&self.path.as_str()) {
            return Err(UpdateError::UnexpectedExecutable {
                path: self.path.clone(),
            });
        }
        Ok(())
    }
}

const fn has_drive_letter(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic()
}

fn truncate_for_report(name: &str) -> String {
    // A malicious name must not be able to put an arbitrary amount of
    // attacker-chosen text into an error message or a log record.
    const LIMIT: usize = 64;
    if name.chars().count() <= LIMIT {
        return name.to_owned();
    }
    name.chars().take(LIMIT).collect::<String>() + "..."
}

/// An update that has passed every check and is cleared to be installed.
#[derive(Clone, Debug)]
pub struct StagedUpdate {
    manifest: VerifiedManifest,
    install_root: String,
    members: Vec<ArchiveMember>,
}

impl StagedUpdate {
    /// Runs the remaining checks and produces the install plan.
    ///
    /// The ordering inside this function is the design: version, then channel
    /// and platform, then the client floor, then per-file digests, and only
    /// then is anything declared installable. Signature verification has
    /// already happened, in [`TrustAnchor::verify`], before either object
    /// existed.
    ///
    /// # Errors
    ///
    /// Returns `InstallRootUnusable` for an empty, over-long, or control-bearing
    /// install root; `ChannelMismatch` or `PlatformMismatch` for a manifest this
    /// build is not entitled to apply (U5); `UnexpectedExecutable` for an
    /// undeclared executable member (U7); and `ArtifactNotInManifest` when the
    /// verified artifact is not covered by the signed manifest (U4).
    pub fn stage(
        manifest: VerifiedManifest,
        artifact: &VerifiedArtifact,
        install_root: &str,
        members: Vec<ArchiveMember>,
        declared_programs: &[&str],
    ) -> Result<Self, UpdateError> {
        if install_root.is_empty() || install_root.len() > MAX_INSTALL_ROOT_BYTES {
            return Err(UpdateError::InstallRootUnusable {
                reason: "install root is empty or implausibly long",
            });
        }
        if install_root.chars().any(char::is_control) {
            return Err(UpdateError::InstallRootUnusable {
                reason: "install root contains a control character",
            });
        }

        // U3. Strictly newer, on the identifier. Not date-based.
        if manifest.version == 0 {
            return Err(UpdateError::DowngradeRefused {
                offered: manifest.version,
                running: 0,
            });
        }

        // U5, checked before the floor so a cross-channel manifest is refused
        // as cross-channel rather than reported as a version problem.
        if manifest.channel != crate::update_path::EXPECTED_CHANNEL {
            return Err(UpdateError::ChannelMismatch {
                offered: manifest.channel,
                expected: EXPECTED_CHANNEL.to_owned(),
            });
        }
        if manifest.platform != crate::update_path::EXPECTED_PLATFORM {
            return Err(UpdateError::PlatformMismatch {
                offered: manifest.platform,
                expected: EXPECTED_PLATFORM.to_owned(),
            });
        }

        for member in &members {
            member.reject_unexpected_executable(declared_programs)?;
        }

        // The artifact is verified; the manifest names it. If the manifest does
        // not list it, the manifest does not cover it and it does not ship.
        let digest = artifact.digest_hex();
        if !manifest
            .entries
            .iter()
            .any(|entry| entry.digest_hex.eq_ignore_ascii_case(&digest))
        {
            return Err(UpdateError::ArtifactNotInManifest);
        }

        Ok(Self {
            manifest,
            install_root: install_root.to_owned(),
            members,
        })
    }

    /// Binds the manifest's client floor to the running version.
    ///
    /// Separate from [`StagedUpdate::stage`] because it needs the running
    /// version, which the caller knows and the manifest does not.
    ///
    /// # Errors
    ///
    /// Returns `DowngradeRefused` if the manifest is not strictly newer than
    /// what is running (U3), `ClientBelowMinimum` if the running version is
    /// under the manifest's floor (U4), and `ManifestMalformed` if the running
    /// version is zero -- which would otherwise make every manifest look
    /// strictly newer and disable U3 entirely.
    pub const fn check_client_floor(&self, running_version: u32) -> Result<(), UpdateError> {
        if running_version == 0 {
            return Err(UpdateError::ManifestMalformed {
                detail: "running version must be greater than zero",
            });
        }
        if manifest_is_not_newer(self.manifest.version, running_version) {
            return Err(UpdateError::DowngradeRefused {
                offered: self.manifest.version,
                running: running_version,
            });
        }
        if running_version < self.manifest.minimum_client_version {
            return Err(UpdateError::ClientBelowMinimum {
                running: running_version,
                minimum: self.manifest.minimum_client_version,
            });
        }
        Ok(())
    }

    /// Produces the plan. Only [`InstallPlan`] can write files.
    #[must_use]
    pub fn plan(self) -> InstallPlan {
        InstallPlan {
            version: self.manifest.version,
            channel: self.manifest.channel,
            platform: self.manifest.platform,
            install_root: self.install_root,
            members: self.members,
        }
    }

    /// The version this update would install.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.manifest.version
    }

    /// The anchor that signed the manifest.
    #[must_use]
    pub const fn signing_key_id(&self) -> &'static str {
        self.manifest.key_id
    }
}

/// Whether an offered version is refused because it is not strictly newer.
///
/// `Ord::le` is not const-stable, so this is written out. The equality arm is
/// part of the rule and not an artefact of the spelling: refusing an equal
/// version is what stops an attacker reinstalling an already-superseded build,
/// and `u3_an_equal_version_is_refused` is what pins it.
const fn manifest_is_not_newer(offered: u32, running: u32) -> bool {
    if offered == running {
        return true;
    }
    offered < running
}

/// The only type in this module that holds write paths.
#[derive(Clone, Debug)]
pub struct InstallPlan {
    version: u32,
    channel: String,
    platform: String,
    install_root: String,
    members: Vec<ArchiveMember>,
}

impl InstallPlan {
    /// The exact set of files this plan would create.
    ///
    /// Every path is `install_root` joined with a member that already passed
    /// [`ArchiveMember::validate`], so the result cannot contain a `..`, an
    /// absolute path, or a component that escapes the root.
    #[must_use]
    pub fn target_paths(&self) -> Vec<String> {
        let root = self.install_root.trim_end_matches('/');
        self.members
            .iter()
            .map(|member| format!("{root}/{}", member.path))
            .collect()
    }

    /// The members whose content still has to be hashed on this machine.
    #[must_use]
    pub fn members(&self) -> &[ArchiveMember] {
        &self.members
    }

    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    #[must_use]
    pub fn channel(&self) -> &str {
        &self.channel
    }

    #[must_use]
    pub fn platform(&self) -> &str {
        &self.platform
    }

    /// A record of the staged update, safe to log.
    ///
    /// Built from [`log_scrubber`] types rather than formatting the plan, so
    /// adding a field to `InstallPlan` cannot silently start writing something
    /// new into logs.
    #[must_use]
    pub fn to_safe_record(&self) -> SafeRecord {
        let executables = self.members.iter().filter(|m| m.is_executable).count();
        SafeRecordBuilder::new()
            .metric("version", u64::from(self.version))
            .state("channel", channel_label(&self.channel))
            .state("platform", platform_label(&self.platform))
            .metric("file_count", self.members.len() as u64)
            .metric("executable_count", executables as u64)
            .build("update.staged")
    }
}

/// A refusal, with the property it enforces.
///
/// Every variant names a rule so an operator reading a log can tell which
/// check fired without matching on string text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpdateError {
    /// U1. No compiled-in anchor accepted the signature.
    SignatureInvalid { key_id: &'static str },
    /// U4. The manifest is not the shape this parser accepts.
    ManifestMalformed { detail: &'static str },
    /// U3. The offered build is not strictly newer.
    DowngradeRefused { offered: u32, running: u32 },
    /// U5. The manifest names a channel this client is not on.
    ChannelMismatch { offered: String, expected: String },
    /// U5. The manifest names a platform this client is not running on.
    PlatformMismatch { offered: String, expected: String },
    /// U4. The client is older than the manifest's floor.
    ClientBelowMinimum { running: u32, minimum: u32 },
    /// U4. The verified artifact is not covered by the manifest.
    ArtifactNotInManifest,
    /// U7. An archive member would write outside the install root.
    UnsafeMemberPath { path: String, reason: &'static str },
    /// U7. An executable member was not declared as a program.
    UnexpectedExecutable { path: String },
    /// The install root itself is not usable.
    InstallRootUnusable { reason: &'static str },
}

impl fmt::Display for UpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SignatureInvalid { key_id } => {
                write!(
                    f,
                    "U1: signature did not verify against any compiled-in key (tried {key_id})"
                )
            }
            Self::ManifestMalformed { detail } => write!(f, "U4: manifest is malformed: {detail}"),
            Self::DowngradeRefused { offered, running } => write!(
                f,
                "U3: manifest version {offered} is not strictly newer than the running {running}"
            ),
            Self::ChannelMismatch { offered, expected } => write!(
                f,
                "U5: manifest channel {offered:?} does not match this client channel {expected:?}"
            ),
            Self::PlatformMismatch { offered, expected } => write!(
                f,
                "U5: manifest platform {offered:?} does not match this client platform {expected:?}"
            ),
            Self::ClientBelowMinimum { running, minimum } => write!(
                f,
                "U4: running version {running} is below the manifest floor {minimum}"
            ),
            Self::ArtifactNotInManifest => {
                f.write_str("U4: verified artifact is not listed in the signed manifest")
            }
            Self::UnsafeMemberPath { path, reason } => {
                write!(f, "U7: archive member {path:?} refused: {reason}")
            }
            Self::UnexpectedExecutable { path } => {
                write!(
                    f,
                    "U7: archive member {path:?} is executable but is not a declared program"
                )
            }
            Self::InstallRootUnusable { reason } => write!(f, "U7: install root refused: {reason}"),
        }
    }
}

impl std::error::Error for UpdateError {}

/// The channel this build is pinned to.
///
/// U6: a constant. A user-selectable channel is U6 by another name, which is
/// why this is not read from anywhere.
pub const EXPECTED_CHANNEL: &str = "stable";

/// The platform this build is pinned to.
pub const EXPECTED_PLATFORM: &str = "windows-x86_64";

/// Lowercase hex, without pulling in a dependency for six lines.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

/// Hashes bytes the way the manifest digests are computed.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
}

/// Builds a [`VerifiedArtifact`] by verifying `payload` against `anchors`.
///
/// This is the only constructor for `VerifiedArtifact`, which is the point:
/// the type cannot be built without a signature check having run.
///
/// # Errors
///
/// Returns `SignatureInvalid` if no compiled-in anchor accepted the signature.
pub fn verify_artifact(
    payload: Vec<u8>,
    anchors: &TrustAnchorSet,
    signature: &Signature,
) -> Result<VerifiedArtifact, UpdateError> {
    let key_id = anchors
        .verify(&payload, signature)
        .ok_or(UpdateError::SignatureInvalid {
            key_id: "<none-of-the-compiled-in-anchors>",
        })?;
    let mut hasher = Sha256::new();
    hasher.update(&payload);
    Ok(VerifiedArtifact {
        digest: hasher.finalize().into(),
        bytes: payload,
        key_id,
    })
}

/// Signs manifest text with a signing key, for building test fixtures.
#[must_use]
pub fn sign(key: &SigningKey, payload: &[u8]) -> Signature {
    key.sign(payload)
}

/// A summary of an update decision for a log record.
#[derive(Clone, Debug)]
pub struct UpdateSummary {
    pub peer: PeerSummary,
    pub outcome: UpdateOutcome,
}

/// Whether an update was applied, and which check stopped it if not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpdateOutcome {
    Staged {
        version: u32,
    },
    Refused {
        rule: &'static str,
        detail: &'static str,
    },
}

impl UpdateOutcome {
    /// The U-number this outcome is governed by.
    #[must_use]
    pub const fn rule(&self) -> &'static str {
        match self {
            Self::Staged { .. } => "U1-U8",
            Self::Refused { rule, .. } => rule,
        }
    }
}

#[cfg(test)]
#[path = "update_path/tests.rs"]
mod tests;
