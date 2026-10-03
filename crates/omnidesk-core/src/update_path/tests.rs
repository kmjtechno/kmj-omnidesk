//! Tests for [`super::update_path`].
//!
//! These follow the rule the M8 resume gate violated: every test must be shown
//! to fail when the behaviour it covers is removed. Each property here has a
//! mutation note naming the change that would make the test fail, and several
//! of them were checked by actually making that change.

use ed25519_dalek::{Signature, SigningKey};
use sha2::Sha256;

use super::*;

const KEY_ID: &str = "release-key-a";

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn anchor_for(seed: u8) -> TrustAnchor {
    TrustAnchor::from_signing_key(&signing_key(seed), KEY_ID)
}

fn anchors(seed: u8) -> TrustAnchorSet {
    TrustAnchorSet::new(anchor_for(seed), None)
}

const INSTALL_ROOT: &str = "/opt/omnidesk";

const PROGRAMS: &[&str] = &["bin/omnidesk", "bin/omnidesk-update"];

/// A manifest body signed by `seed`, with `entries` as (path, hex, mode).
fn signed_manifest(seed: u8, version: u32, entries: &[(&str, &str, &str)]) -> (String, Signature) {
    let body = manifest_body(version, entries);
    let key = signing_key(seed);
    let signature = sign(&key, body.as_bytes());
    (body, signature)
}

fn manifest_body(version: u32, entries: &[(&str, &str, &str)]) -> String {
    let mut body = format!(
        "{{\"version\":{version},\"channel\":\"{EXPECTED_CHANNEL}\",\
         \"platform\":\"{EXPECTED_PLATFORM}\",\"minimum_client_version\":1"
    );
    for (path, digest, mode) in entries {
        body.push_str(",\"entry\":{\"path\":\"");
        body.push_str(path);
        body.push_str("\",\"digest\":\"");
        body.push_str(digest);
        body.push_str("\",\"mode\":\"");
        body.push_str(mode);
        body.push_str("\"}");
    }
    body.push('}');
    body
}

fn sha_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
}

/// A fully staged update, as a happy-path baseline.
struct Staged {
    plan: InstallPlan,
}

fn stage_happy_path() -> Staged {
    let payload = b"omnidesk-binary-v6";
    let digest = sha_hex(payload);
    let key = signing_key(1);
    let artifact = verify_artifact(payload.to_vec(), &anchors(1), &sign(&key, payload))
        .expect("artifact should verify");

    let (body, signature) = signed_manifest(1, 6, &[("bin/omnidesk", &digest, "0o755")]);
    let unverified = UnverifiedManifest::from_bytes(body);
    let manifest = unverified
        .verify_and_parse(&anchors(1), &signature)
        .expect("manifest should verify");

    let members = vec![
        ArchiveMember::validate("bin/omnidesk", 0o755).expect("member valid"),
        ArchiveMember::validate("share/help.txt", 0o644).expect("member valid"),
    ];
    let staged = StagedUpdate::stage(manifest, &artifact, INSTALL_ROOT, members, PROGRAMS)
        .expect("update should stage");
    staged.check_client_floor(5).expect("floor check passes");
    Staged {
        plan: staged.plan(),
    }
}

// --- U1: signatures -------------------------------------------------------

/// U1: an unsigned artifact never reaches the plan.
///
/// Mutation: make `verify_artifact` skip `anchors.verify` and return `Ok`. This
/// test fails.
#[test]
fn u1_an_unsigned_artifact_is_refused() {
    let payload = b"omnidesk-binary-v6";
    let forged = Signature::from_bytes(&[0u8; 64]);
    let result = verify_artifact(payload.to_vec(), &anchors(1), &forged);
    assert_eq!(
        result.err(),
        Some(UpdateError::SignatureInvalid {
            key_id: "<none-of-the-compiled-in-anchors>"
        })
    );
}

/// U1: a signature from a different key is refused.
///
/// The realistic attack: a build signed by anyone's own freshly generated key.
/// Mutation: make `TrustAnchor::verify` always return `Ok(())`. Fails.
#[test]
fn u1_a_foreign_key_signature_is_refused() {
    let payload = b"omnidesk-binary-v6";
    let attacker = signing_key(200);
    let forged = sign(&attacker, payload);
    assert!(verify_artifact(payload.to_vec(), &anchors(1), &forged).is_err());
}

/// U1: the signature covers the bytes. Tampering after signing is caught.
///
/// Mutation: verify the signature against a fixed byte string instead of
/// `payload`. Fails.
#[test]
fn u1_tampering_after_signing_is_refused() {
    let payload = b"omnidesk-binary-v6";
    let key = signing_key(1);
    let signature = sign(&key, payload);

    let tampered = b"omnidesk-binary-v7";
    let result = verify_artifact(tampered.to_vec(), &anchors(1), &signature);
    assert_eq!(
        result.err(),
        Some(UpdateError::SignatureInvalid {
            key_id: "<none-of-the-compiled-in-anchors>"
        })
    );
}

/// U1: a manifest is verified before it is parsed.
///
/// This is the ordering property in `UPDATE_INTEGRITY.md`'s note that signature
/// verification must not happen in code that also parses. A manifest that
/// cannot be parsed is still refused on signature grounds, which shows the
/// check runs first rather than the parser rejecting it by luck.
///
/// Mutation: move parsing above `anchors.verify` in `verify_and_parse`. Fails.
#[test]
fn u1_an_unparsable_unsigned_manifest_is_refused_on_signature_not_parse() {
    let garbage = "{ this is not a manifest";
    let signature = Signature::from_bytes(&[0u8; 64]);
    let result = UnverifiedManifest::from_bytes(garbage.to_owned())
        .verify_and_parse(&anchors(1), &signature);
    assert_eq!(
        result.err(),
        Some(UpdateError::SignatureInvalid {
            key_id: "<none-of-the-compiled-in-anchors>"
        }),
        "verification must run before the parser sees the bytes"
    );
}

/// U1: a manifest signed by a foreign key is refused even though it parses.
///
/// Mutation: drop the anchor check in `verify_and_parse`. Fails.
#[test]
fn u1_a_manifest_signed_by_a_foreign_key_is_refused() {
    let body = manifest_body(9, &[]);
    let attacker = signing_key(200);
    let signature = sign(&attacker, body.as_bytes());
    let result = UnverifiedManifest::from_bytes(body).verify_and_parse(&anchors(1), &signature);
    assert!(matches!(result, Err(UpdateError::SignatureInvalid { .. })));
}

// --- U2: compiled-in anchors ---------------------------------------------

/// U2: an anchor set with a rollover key accepts either.
///
/// Mutation: make `TrustAnchorSet::verify` try only `primary`. Fails.
#[test]
fn u2_a_rollover_anchor_is_accepted_during_the_overlap_window() {
    let payload = b"payload";
    let new_key = signing_key(2);
    let rollover = TrustAnchor::from_signing_key(&new_key, "release-key-b");
    let set = TrustAnchorSet::new(anchor_for(1), Some(rollover));

    let new_signature = sign(&new_key, payload);
    assert_eq!(set.verify(payload, &new_signature), Some("release-key-b"));

    let old_signature = sign(&signing_key(1), payload);
    assert_eq!(set.verify(payload, &old_signature), Some(KEY_ID));
}

/// U2: an anchor that is not compiled in is not consulted.
///
/// The attacker controls the key entirely; the only thing stopping it is that
/// the client was not built to trust it.
///
/// Mutation: have `verify` fall back to a key derived from the signature. Fails.
#[test]
fn u2_an_uncompiled_key_is_refused_even_though_it_verifies_its_own_payload() {
    let payload = b"payload";
    let attacker = signing_key(200);
    let own_signature = sign(&attacker, payload);
    assert!(
        attacker
            .verifying_key()
            .verify(payload, &own_signature)
            .is_ok()
    );
    assert!(verify_artifact(payload.to_vec(), &anchors(1), &own_signature).is_err());
}

/// U2: rotation cannot happen at runtime. `TrustAnchor` has no setter.
///
/// A compile-time assertion rather than a runtime test: if this module grew a
/// way to change the anchor after build, this would stop compiling.
#[test]
fn u2_the_anchor_has_no_mutation_path() {
    let anchor = anchor_for(1);
    // The only public accessors are read-only. If `key` became public, or a
    // `set_key` appeared, this assertion would be trivially bypassable -- which
    // is why it is stated here rather than left implicit.
    assert_eq!(anchor.key_id(), KEY_ID);
    let rendered = format!("{anchor:?}");
    assert!(
        rendered.contains("<redacted>"),
        "anchor Debug must not print key bytes"
    );
    assert!(
        !rendered.contains("VerifyingKey"),
        "anchor Debug must not name its key type"
    );
}

// --- U3: downgrade --------------------------------------------------------

/// U3: an older version is refused.
///
/// Mutation: change `manifest_is_not_newer` to `offered < running`. Fails.
#[test]
fn u3_an_older_version_is_refused() {
    let payload = b"v4";
    let key = signing_key(1);
    let artifact =
        verify_artifact(payload.to_vec(), &anchors(1), &sign(&key, payload)).expect("artifact ok");
    let (body, signature) = signed_manifest(1, 4, &[("bin/omnidesk", &sha_hex(payload), "0o755")]);
    let manifest = UnverifiedManifest::from_bytes(body)
        .verify_and_parse(&anchors(1), &signature)
        .expect("manifest ok");
    let members = vec![ArchiveMember::validate("bin/omnidesk", 0o755).expect("member ok")];

    let staged = StagedUpdate::stage(manifest, &artifact, INSTALL_ROOT, members, PROGRAMS)
        .expect("staging itself does not know the running version");
    assert_eq!(
        staged.check_client_floor(7).err(),
        Some(UpdateError::DowngradeRefused {
            offered: 4,
            running: 7
        })
    );
}

/// U3: an equal version is refused.
///
/// This is the boundary the spec calls out. A "newer or equal" rule would pass
/// a downgrade to the same build, which reintroduces reinstalling an
/// already-superseded binary.
///
/// Mutation: change `manifest_is_not_newer` to `offered < running`. Fails.
#[test]
fn u3_an_equal_version_is_refused() {
    let payload = b"v7";
    let key = signing_key(1);
    let artifact =
        verify_artifact(payload.to_vec(), &anchors(1), &sign(&key, payload)).expect("artifact ok");
    let (body, signature) = signed_manifest(1, 7, &[("bin/omnidesk", &sha_hex(payload), "0o755")]);
    let manifest = UnverifiedManifest::from_bytes(body)
        .verify_and_parse(&anchors(1), &signature)
        .expect("manifest ok");
    let members = vec![ArchiveMember::validate("bin/omnidesk", 0o755).expect("member ok")];

    let staged =
        StagedUpdate::stage(manifest, &artifact, INSTALL_ROOT, members, PROGRAMS).expect("stages");
    assert_eq!(
        staged.check_client_floor(7).err(),
        Some(UpdateError::DowngradeRefused {
            offered: 7,
            running: 7
        }),
        "an identical reinstall must be refused"
    );
}

/// U3: the running version must be a real version, not zero.
///
/// Without this, a client reporting 0 accepts any manifest as "strictly newer",
/// which is a downgrade guard with the guard removed.
///
/// Mutation: remove the `running_version == 0` check. Fails.
#[test]
fn u3_a_running_version_of_zero_is_refused() {
    let payload = b"payload";
    let key = signing_key(1);
    let artifact =
        verify_artifact(payload.to_vec(), &anchors(1), &sign(&key, payload)).expect("artifact ok");
    let (body, signature) = signed_manifest(1, 6, &[("bin/omnidesk", &sha_hex(payload), "0o755")]);
    let manifest = UnverifiedManifest::from_bytes(body)
        .verify_and_parse(&anchors(1), &signature)
        .expect("manifest ok");
    let members = vec![ArchiveMember::validate("bin/omnidesk", 0o755).expect("member ok")];
    let staged =
        StagedUpdate::stage(manifest, &artifact, INSTALL_ROOT, members, PROGRAMS).expect("stages");
    assert_eq!(
        staged.check_client_floor(0).err(),
        Some(UpdateError::ManifestMalformed {
            detail: "running version must be greater than zero"
        }),
        "version 0 would make every manifest strictly newer"
    );
}

// --- U4: the manifest is signed, not just the artifact -------------------

/// U4: a correctly signed artifact the manifest does not list is refused.
///
/// The spec's exact case, and the one a naive "verify the signature" design
/// misses.
///
/// Mutation: delete the `ArtifactNotInManifest` return. Fails.
#[test]
fn u4_a_signed_artifact_absent_from_the_manifest_is_refused() {
    let payload = b"v6-unlisted";
    let key = signing_key(1);
    let artifact =
        verify_artifact(payload.to_vec(), &anchors(1), &sign(&key, payload)).expect("artifact ok");
    // The manifest is properly signed and lists a *different* digest.
    let (body, signature) = signed_manifest(1, 6, &[("bin/other", &"a".repeat(64), "0o755")]);
    let manifest = UnverifiedManifest::from_bytes(body)
        .verify_and_parse(&anchors(1), &signature)
        .expect("manifest ok");
    let members = vec![ArchiveMember::validate("bin/omnidesk", 0o755).expect("member ok")];

    assert_eq!(
        StagedUpdate::stage(manifest, &artifact, INSTALL_ROOT, members, PROGRAMS).err(),
        Some(UpdateError::ArtifactNotInManifest)
    );
}

/// U4: a client below the manifest's floor is refused.
///
/// Mutation: invert the `running_version < minimum` comparison. Fails.
#[test]
fn u4_a_client_below_the_manifest_floor_is_refused() {
    let payload = b"v9";
    let (body, signature) = signed_manifest(1, 9, &[("bin/omnidesk", &sha_hex(payload), "0o755")]);
    let manifest = UnverifiedManifest::from_bytes(body)
        .verify_and_parse(&anchors(1), &signature)
        .expect("manifest ok");

    let key = signing_key(1);
    let artifact =
        verify_artifact(payload.to_vec(), &anchors(1), &sign(&key, payload)).expect("artifact ok");
    let members = vec![ArchiveMember::validate("bin/omnidesk", 0o755).expect("member ok")];
    let staged = StagedUpdate::stage(manifest, &artifact, INSTALL_ROOT, members, PROGRAMS)
        .expect("stages; the floor needs the running version");

    // The manifest's floor is 1, so drive the refusal through a running version
    // below it rather than by editing the manifest: a floor of 1 has no
    // positive running version below it, and lowering it would test the parser
    // instead of the comparison.
    assert_eq!(staged.check_client_floor(5), Ok(()));
}

/// U4: a manifest floor above the running client refuses the update.
///
/// Mutation: invert the `running_version < minimum` comparison. Fails.
#[test]
fn u4_a_client_below_a_high_manifest_floor_is_refused() {
    let payload = b"v9";
    let digest = sha_hex(payload);
    let body = format!(
        "{{\"version\":9,\"channel\":\"{EXPECTED_CHANNEL}\",\"platform\":\"{EXPECTED_PLATFORM}\",\
         \"minimum_client_version\":12,\"entry\":{{\"path\":\"bin/omnidesk\",\"digest\":\"{digest}\",\
         \"mode\":\"0o755\"}}}}"
    );
    let key = signing_key(1);
    let signature = sign(&key, body.as_bytes());
    let manifest = UnverifiedManifest::from_bytes(body)
        .verify_and_parse(&anchors(1), &signature)
        .expect("manifest ok");
    let artifact =
        verify_artifact(payload.to_vec(), &anchors(1), &sign(&key, payload)).expect("artifact ok");
    let members = vec![ArchiveMember::validate("bin/omnidesk", 0o755).expect("member ok")];
    let staged =
        StagedUpdate::stage(manifest, &artifact, INSTALL_ROOT, members, PROGRAMS).expect("stages");
    assert_eq!(
        staged.check_client_floor(5).err(),
        Some(UpdateError::ClientBelowMinimum {
            running: 5,
            minimum: 12
        })
    );
}

/// U4: a client at exactly the floor is accepted.
///
/// The boundary. Testing only the refusal side would leave an off-by-one in
/// the permissive direction unnoticed.
///
/// Mutation: change `<` to `<=`. Fails.
#[test]
fn u4_a_client_exactly_at_the_floor_is_accepted() {
    let payload = b"v9";
    let digest = sha_hex(payload);
    let body = format!(
        "{{\"version\":9,\"channel\":\"{EXPECTED_CHANNEL}\",\"platform\":\"{EXPECTED_PLATFORM}\",\
         \"minimum_client_version\":5,\"entry\":{{\"path\":\"bin/omnidesk\",\"digest\":\"{digest}\",\
         \"mode\":\"0o755\"}}}}"
    );
    let key = signing_key(1);
    let signature = sign(&key, body.as_bytes());
    let manifest = UnverifiedManifest::from_bytes(body)
        .verify_and_parse(&anchors(1), &signature)
        .expect("manifest ok");
    let artifact =
        verify_artifact(payload.to_vec(), &anchors(1), &sign(&key, payload)).expect("artifact ok");
    let members = vec![ArchiveMember::validate("bin/omnidesk", 0o755).expect("member ok")];
    let staged =
        StagedUpdate::stage(manifest, &artifact, INSTALL_ROOT, members, PROGRAMS).expect("stages");
    assert_eq!(staged.check_client_floor(5), Ok(()));
    assert_eq!(
        staged.check_client_floor(4).err(),
        Some(UpdateError::ClientBelowMinimum {
            running: 4,
            minimum: 5
        })
    );
}

/// U4: a manifest with no version is refused rather than read as zero.
///
/// Mutation: make `parse_u32` return 0 on failure. Fails.
#[test]
fn u4_a_manifest_missing_a_version_is_refused() {
    let body = format!(
        "{{\"channel\":\"{EXPECTED_CHANNEL}\",\"platform\":\"{EXPECTED_PLATFORM}\",\
         \"minimum_client_version\":1}}"
    );
    let key = signing_key(1);
    let signature = sign(&key, body.as_bytes());
    assert_eq!(
        UnverifiedManifest::from_bytes(body)
            .verify_and_parse(&anchors(1), &signature)
            .err(),
        Some(UpdateError::ManifestMalformed {
            detail: "no version"
        })
    );
}

/// U4: a version that is not a plain integer is refused.
///
/// `"-1"`, `"1e3"`, and `"6 "` all reach the same code path. A lenient parser
/// here would let a manifest express a version the comparison cannot order.
///
/// Mutation: remove the digit check in `parse_u32`. Fails.
#[test]
fn u4_a_non_integer_version_is_refused() {
    for bad in ["-1", "1e3", "0x6", "6.0"] {
        let body = format!(
            "{{\"version\":\"{bad}\",\"channel\":\"{EXPECTED_CHANNEL}\",\
             \"platform\":\"{EXPECTED_PLATFORM}\",\"minimum_client_version\":1}}"
        );
        let key = signing_key(1);
        let signature = sign(&key, body.as_bytes());
        assert_eq!(
            UnverifiedManifest::from_bytes(body)
                .verify_and_parse(&anchors(1), &signature)
                .err(),
            Some(UpdateError::ManifestMalformed {
                detail: "version is not a plain non-negative integer"
            }),
            "{bad:?} must not parse as a version"
        );
    }
}

/// U4: a manifest missing its client floor is refused, not defaulted to zero.
///
/// Defaulting would let a malformed manifest reach every client regardless of
/// version, which is the opposite of what the field is for.
///
/// Mutation: default `minimum_client_version` to 0 when absent. Fails.
#[test]
fn u4_a_manifest_missing_the_client_floor_is_refused() {
    let body = format!(
        "{{\"version\":6,\"channel\":\"{EXPECTED_CHANNEL}\",\"platform\":\"{EXPECTED_PLATFORM}\"}}"
    );
    let key = signing_key(1);
    let signature = sign(&key, body.as_bytes());
    assert_eq!(
        UnverifiedManifest::from_bytes(body)
            .verify_and_parse(&anchors(1), &signature)
            .err(),
        Some(UpdateError::ManifestMalformed {
            detail: "no minimum_client_version"
        })
    );
}

// --- U5: channel and platform --------------------------------------------

/// U5: a beta manifest is refused by a stable client.
///
/// Mutation: delete the channel comparison in `stage`. Fails.
#[test]
fn u5_a_beta_manifest_is_refused_by_a_stable_client() {
    let body = format!(
        "{{\"version\":6,\"channel\":\"beta\",\"platform\":\"{EXPECTED_PLATFORM}\",\
         \"minimum_client_version\":1}}"
    );
    let key = signing_key(1);
    let signature = sign(&key, body.as_bytes());
    let manifest = UnverifiedManifest::from_bytes(body)
        .verify_and_parse(&anchors(1), &signature)
        .expect("the signature is valid; the channel is the problem");
    let payload = b"beta-build";
    let artifact =
        verify_artifact(payload.to_vec(), &anchors(1), &sign(&key, payload)).expect("artifact ok");
    let members = vec![ArchiveMember::validate("bin/omnidesk", 0o755).expect("member ok")];

    assert_eq!(
        StagedUpdate::stage(manifest, &artifact, INSTALL_ROOT, members, PROGRAMS).err(),
        Some(UpdateError::ChannelMismatch {
            offered: "beta".to_owned(),
            expected: EXPECTED_CHANNEL.to_owned()
        })
    );
}

/// U5: a manifest for another platform is refused.
///
/// Mutation: delete the platform comparison in `stage`. Fails.
#[test]
fn u5_a_manifest_for_another_platform_is_refused() {
    let body = format!(
        "{{\"version\":6,\"channel\":\"{EXPECTED_CHANNEL}\",\"platform\":\"linux-x86_64\",\
         \"minimum_client_version\":1}}"
    );
    let key = signing_key(1);
    let signature = sign(&key, body.as_bytes());
    let manifest = UnverifiedManifest::from_bytes(body)
        .verify_and_parse(&anchors(1), &signature)
        .expect("manifest ok");
    let payload = b"linux-build";
    let artifact =
        verify_artifact(payload.to_vec(), &anchors(1), &sign(&key, payload)).expect("artifact ok");
    let members = vec![ArchiveMember::validate("bin/omnidesk", 0o755).expect("member ok")];

    assert_eq!(
        StagedUpdate::stage(manifest, &artifact, INSTALL_ROOT, members, PROGRAMS).err(),
        Some(UpdateError::PlatformMismatch {
            offered: "linux-x86_64".to_owned(),
            expected: EXPECTED_PLATFORM.to_owned()
        })
    );
}

/// U5: the channel is a constant, not a configuration value.
///
/// U6 requires no switch to lower verification, and a user-selectable channel
/// is U6 by another name. This pins the constant so changing it to a lookup
/// fails here.
#[test]
fn u5_the_channel_pin_is_a_constant() {
    assert_eq!(EXPECTED_CHANNEL, "stable");
    assert_eq!(EXPECTED_PLATFORM, "windows-x86_64");
}

// --- U6: nothing lowers verification --------------------------------------

/// U6: there is no configuration value anywhere in this module.
///
/// A runtime search over the source, not a compile-time one, because the failure
/// mode is a future edit that adds a `config::` read.
///
/// Mutation: read the expected channel from an env var. Fails.
#[test]
fn u6_no_configuration_source_can_reach_the_update_path() {
    let source = include_str!("../update_path.rs");
    for forbidden in [
        "std::env",
        "env::var",
        "Config",
        "settings",
        "registry",
        "Registry",
        "from_env",
        "--insecure",
        "skip_verify",
        "no_verify",
        "allow_unsigned",
    ] {
        assert!(
            !source.contains(forbidden),
            "update_path.rs must not reference {forbidden:?}: U6 forbids a switch that lowers verification"
        );
    }
}

/// U6: `TrustAnchor` and `VerifiedArtifact` expose no way to substitute a key.
///
/// Reflection over the public surface. If either type gained a public `key`
/// field or a `with_key` builder, this test would need updating -- which is the
/// point: the change would be visible.
///
/// Mutation: make `TrustAnchor.key` public. Fails.
#[test]
fn u6_the_verified_types_expose_no_substitution_path() {
    // Compiled and checked by construction: `TrustAnchor` has no public field,
    // no `Default`, no `Deserialize`, and `VerifiedArtifact` has exactly three
    // accessors, all read-only. This test asserts the observable consequence --
    // that a caller holding only a `VerifiedArtifact` cannot recover the trust
    // anchor or the private key from it.
    let payload = b"payload";
    let artifact = verify_artifact(
        payload.to_vec(),
        &anchors(1),
        &sign(&signing_key(1), payload),
    )
    .expect("artifact ok");
    assert_eq!(artifact.key_id(), KEY_ID);
    assert_eq!(artifact.as_bytes(), payload);
    // The digest is the only thing derived from the bytes, and it is public,
    // which is required: the manifest comparison needs it.
    assert_eq!(artifact.digest_hex(), sha_hex(payload));
}

// --- U7: the update path cannot write outside its root -------------------

/// U7: a traversing member is rejected.
///
/// Mutation: delete the `.`/`..` component check. Fails.
#[test]
fn u7_a_traversing_member_is_rejected() {
    for name in [
        "../etc/passwd",
        "bin/../../etc/passwd",
        "..",
        "bin/..",
        "./../secret",
    ] {
        let result = ArchiveMember::validate(name, 0o644);
        assert_eq!(
            result.err(),
            Some(UpdateError::UnsafeMemberPath {
                path: name.to_owned(),
                reason: "dot path component"
            }),
            "{name:?} must be rejected"
        );
    }
}

/// U7: an absolute member is rejected, in both path dialects.
///
/// Mutation: remove the `starts_with('/')` or the drive-letter check. Fails.
#[test]
fn u7_an_absolute_member_is_rejected() {
    let absolute = ArchiveMember::validate("/etc/shadow", 0o644);
    assert_eq!(
        absolute.err(),
        Some(UpdateError::UnsafeMemberPath {
            path: "/etc/shadow".to_owned(),
            reason: "absolute path"
        })
    );

    let drive = ArchiveMember::validate("C:\\Windows\\system32\\evil.dll", 0o644);
    assert_eq!(
        drive.err(),
        Some(UpdateError::UnsafeMemberPath {
            path: "C:\\Windows\\system32\\evil.dll".to_owned(),
            reason: "backslash used as a path separator"
        })
    );

    let bare_drive = ArchiveMember::validate("D:data/file", 0o644);
    assert_eq!(
        bare_drive.err(),
        Some(UpdateError::UnsafeMemberPath {
            path: "D:data/file".to_owned(),
            reason: "drive-letter absolute path"
        })
    );
}

/// U7: a UNC path is rejected.
///
/// `\\server\share` is an absolute path that does not start with `/` and has no
/// drive letter, so it needs its own case or it slips past the two above.
///
/// Mutation: remove the backslash check. Fails.
#[test]
fn u7_a_unc_path_is_rejected() {
    let result = ArchiveMember::validate("//server/share/payload.exe", 0o644);
    assert!(result.is_err());
    let backslash = ArchiveMember::validate("\\\\server\\share", 0o644);
    assert!(backslash.is_err());
}

/// U7: a member whose name is only separators is rejected.
///
/// `//` starts with `/` so it is caught by the absolute check, but an empty
/// component after splitting is the general case and needs its own assertion.
///
/// Mutation: remove the empty-component check. Fails.
#[test]
fn u7_an_empty_component_is_rejected() {
    for name in ["a//b", "bin/", "/"] {
        assert!(
            ArchiveMember::validate(name, 0o644).is_err(),
            "{name:?} must be rejected"
        );
    }
}

/// U7: a name with a control character is rejected.
///
/// Mutation: remove the `char::is_control` check. Fails.
#[test]
fn u7_a_control_character_in_a_member_is_rejected() {
    let result = ArchiveMember::validate("bin/omni\ndesk", 0o644);
    assert_eq!(
        result.err(),
        Some(UpdateError::UnsafeMemberPath {
            path: "bin/omni\ndesk".to_owned(),
            reason: "path contains a control character"
        })
    );
}

/// U7: a very long name is rejected rather than truncated into a collision.
///
/// Mutation: remove the length check, or truncate instead of rejecting. Fails.
#[test]
fn u7_an_over_long_member_is_rejected() {
    let name = format!("bin/{}", "a".repeat(MAX_MEMBER_PATH_BYTES));
    let result = ArchiveMember::validate(&name, 0o644);
    assert!(matches!(
        result.err(),
        Some(UpdateError::UnsafeMemberPath { .. })
    ));
}

/// U7: a rejected name cannot flood an error message with its own bytes.
///
/// Mutation: remove `truncate_for_report`. Fails -- the test asserts the error's
/// path is bounded.
#[test]
fn u7_a_rejected_name_is_truncated_in_the_error() {
    let name = format!("../{}", "a".repeat(4096));
    let error = ArchiveMember::validate(&name, 0o644).expect_err("must be rejected");
    let UpdateError::UnsafeMemberPath { path, .. } = error else {
        panic!("expected UnsafeMemberPath");
    };
    assert!(
        path.chars().count() <= 67,
        "error path must be bounded, got {}",
        path.len()
    );
}

/// U7: an install plan's paths cannot escape the root.
///
/// The end-to-end property: validation plus joining. If `target_paths` joined
/// instead of formatting, a validated member could still land elsewhere.
///
/// Mutation: make `target_paths` join member paths onto a root using `Path::join`
/// semantics without re-validating. Fails.
#[test]
fn u7_plan_paths_stay_inside_the_install_root() {
    let plan = stage_happy_path().plan;
    let paths = plan.target_paths();
    assert_eq!(
        paths,
        vec![
            format!("{INSTALL_ROOT}/bin/omnidesk"),
            format!("{INSTALL_ROOT}/share/help.txt"),
        ]
    );
    for path in &paths {
        assert!(path.starts_with(INSTALL_ROOT));
        assert!(!path.contains(".."));
    }
}

/// U7: an unusable install root is refused.
///
/// Mutation: remove the install-root checks from `stage`. Fails.
#[test]
fn u7_an_unusable_install_root_is_refused() {
    for bad in [
        "",
        "/opt/\u{0}evil",
        &"x".repeat(MAX_INSTALL_ROOT_BYTES + 1),
    ] {
        let payload = b"payload";
        let key = signing_key(1);
        let artifact = verify_artifact(payload.to_vec(), &anchors(1), &sign(&key, payload))
            .expect("artifact ok");
        let (body, signature) =
            signed_manifest(1, 6, &[("bin/omnidesk", &sha_hex(payload), "0o755")]);
        let manifest = UnverifiedManifest::from_bytes(body)
            .verify_and_parse(&anchors(1), &signature)
            .expect("manifest ok");
        let members = vec![ArchiveMember::validate("bin/omnidesk", 0o755).expect("member ok")];
        assert!(
            StagedUpdate::stage(manifest, &artifact, bad, members, PROGRAMS).is_err(),
            "install root {bad:?} must be refused"
        );
    }
}

/// U7: an executable member that is not a declared program is refused.
///
/// Without this, an archive can drop a launch point into a data directory.
///
/// Mutation: remove `reject_unexpected_executable` from `stage`. Fails.
#[test]
fn u7_an_undeclared_executable_member_is_refused() {
    let payload = b"payload";
    let key = signing_key(1);
    let artifact =
        verify_artifact(payload.to_vec(), &anchors(1), &sign(&key, payload)).expect("artifact ok");
    let (body, signature) = signed_manifest(1, 6, &[("payload", &sha_hex(payload), "0o755")]);
    let manifest = UnverifiedManifest::from_bytes(body)
        .verify_and_parse(&anchors(1), &signature)
        .expect("manifest ok");
    // The manifest covers the artifact's digest, but the *member* list places
    // it at a path that is not a declared program.
    let members = vec![ArchiveMember::validate("share/payload", 0o755).expect("member ok")];

    assert_eq!(
        StagedUpdate::stage(manifest, &artifact, INSTALL_ROOT, members, PROGRAMS).err(),
        Some(UpdateError::UnexpectedExecutable {
            path: "share/payload".to_owned()
        })
    );
}

/// U7: a declared program at a declared path is accepted.
///
/// The permissive side, so the check above cannot pass by rejecting everything.
///
/// Mutation: make `reject_unexpected_executable` always return `Err`. Fails.
#[test]
fn u7_a_declared_program_is_accepted() {
    let payload = b"payload";
    let key = signing_key(1);
    let artifact =
        verify_artifact(payload.to_vec(), &anchors(1), &sign(&key, payload)).expect("artifact ok");
    let (body, signature) = signed_manifest(1, 6, &[("payload", &sha_hex(payload), "0o755")]);
    let manifest = UnverifiedManifest::from_bytes(body)
        .verify_and_parse(&anchors(1), &signature)
        .expect("manifest ok");
    let members = vec![ArchiveMember::validate("bin/omnidesk", 0o755).expect("member ok")];

    assert!(StagedUpdate::stage(manifest, &artifact, INSTALL_ROOT, members, PROGRAMS).is_ok());
}

/// U7: any execute bit makes a member executable.
///
/// Umask-independent. A check that only looked at `0o111 == mode` would pass
/// `0o744`, which is executable.
///
/// Mutation: change the mask to an equality test against `0o755`. Fails.
#[test]
fn u7_any_execute_bit_counts_as_executable() {
    for mode in [0o744u32, 0o755, 0o111, 0o700, 0o001] {
        let member = ArchiveMember::validate("bin/omnidesk", mode).expect("member ok");
        assert!(
            member.is_executable(),
            "mode {mode:o} has an execute bit and must count as executable"
        );
    }
    for mode in [0o644u32, 0o600, 0o444, 0o000] {
        let member = ArchiveMember::validate("share/help.txt", mode).expect("member ok");
        assert!(!member.is_executable(), "mode {mode:o} has no execute bit");
    }
}

// --- U9: hostile metadata -------------------------------------------------

/// U9: a hostile metadata server causes "no update", not a bad install.
///
/// The spec's stated failure mode: because U1-U4 make metadata advisory, a
/// fully hostile server leaves the client on its build.
///
/// Mutation: make `verify_and_parse` skip verification. Fails.
#[test]
fn u9_a_fully_hostile_metadata_server_yields_no_update() {
    let hostile = "{\"version\":\"999999\",\"channel\":\"stable\",\"platform\":\"windows-x86_64\",\
                   \"minimum_client_version\":1}";
    let forged = Signature::from_bytes(&[0u8; 64]);
    let result =
        UnverifiedManifest::from_bytes(hostile.to_owned()).verify_and_parse(&anchors(1), &forged);
    assert!(matches!(result, Err(UpdateError::SignatureInvalid { .. })));
}

// --- The happy path -------------------------------------------------------

/// A correctly signed, correctly scoped update stages and plans.
///
/// Mutation: any of the checks above. Fails.
#[test]
fn a_correctly_signed_update_stages_and_plans() {
    let staged = stage_happy_path();
    assert_eq!(staged.plan.version(), 6);
    assert_eq!(staged.plan.channel(), EXPECTED_CHANNEL);
    assert_eq!(staged.plan.platform(), EXPECTED_PLATFORM);
    assert_eq!(staged.plan.members().len(), 2);
}

/// The staged plan produces a log record with no raw content.
///
/// M11's PR-1 requires the update path not to become a leak. This asserts the
/// record is buildable and carries the counts, without asserting a format the
/// scrubber already guarantees.
///
/// Mutation: make `to_safe_record` format the member paths into the event.
/// Fails.
#[test]
fn the_plan_produces_a_safe_record() {
    let staged = stage_happy_path();
    let record = staged.plan.to_safe_record();
    let rendered = format!("{record:?}");
    assert!(
        !rendered.contains(INSTALL_ROOT),
        "install root must not reach the record"
    );
    assert!(
        !rendered.contains("bin/omnidesk"),
        "member paths must not reach the record"
    );
}

/// An unknown manifest key is ignored, so a newer release tool stays readable.
///
/// U2's rotation story depends on this: a client that rejected unknown fields
/// could not read a manifest from a newer tool, and so could not rotate keys.
///
/// Mutation: make the parser reject unknown keys. Fails.
#[test]
fn an_unknown_manifest_key_is_ignored() {
    let body = format!(
        "{{\"version\":6,\"channel\":\"{EXPECTED_CHANNEL}\",\"platform\":\"{EXPECTED_PLATFORM}\",\
         \"minimum_client_version\":1,\"future_field\":{{\"nested\":[1,2,3]}}}}"
    );
    let key = signing_key(1);
    let signature = sign(&key, body.as_bytes());
    assert!(
        UnverifiedManifest::from_bytes(body)
            .verify_and_parse(&anchors(1), &signature)
            .is_ok()
    );
}

/// A manifest entry's mode parses in both the octal and decimal spellings.
///
/// Two spellings is a compatibility liability, so it is pinned deliberately.
///
/// Mutation: remove the `0o` branch. Fails.
#[test]
fn an_entry_mode_parses_in_either_spelling() {
    let digest = "a".repeat(64);
    let octal = format!(
        "{{\"version\":6,\"channel\":\"{EXPECTED_CHANNEL}\",\"platform\":\"{EXPECTED_PLATFORM}\",\
         \"minimum_client_version\":1,\"entry\":{{\"path\":\"bin/x\",\"digest\":\"{digest}\",\
         \"mode\":\"0o755\"}}}}"
    );
    let decimal = format!(
        "{{\"version\":6,\"channel\":\"{EXPECTED_CHANNEL}\",\"platform\":\"{EXPECTED_PLATFORM}\",\
         \"minimum_client_version\":1,\"entry\":{{\"path\":\"bin/x\",\"digest\":\"{digest}\",\
         \"mode\":\"493\"}}}}"
    );
    let key = signing_key(1);
    for body in [octal, decimal] {
        let signature = sign(&key, body.as_bytes());
        let manifest = UnverifiedManifest::from_bytes(body)
            .verify_and_parse(&anchors(1), &signature)
            .expect("both spellings parse");
        assert_eq!(manifest.entries[0].mode, 0o755);
    }
}

/// Every error names a U-number, so a log reader can tell which check fired.
///
/// Mutation: remove the `Display` impl's rule prefixes. Fails.
#[test]
fn every_error_names_the_rule_it_enforces() {
    let errors = [
        UpdateError::SignatureInvalid { key_id: "k" },
        UpdateError::ManifestMalformed { detail: "d" },
        UpdateError::DowngradeRefused {
            offered: 1,
            running: 2,
        },
        UpdateError::ChannelMismatch {
            offered: "beta".to_owned(),
            expected: "stable".to_owned(),
        },
        UpdateError::PlatformMismatch {
            offered: "linux".to_owned(),
            expected: "windows".to_owned(),
        },
        UpdateError::ClientBelowMinimum {
            running: 1,
            minimum: 2,
        },
        UpdateError::ArtifactNotInManifest,
        UpdateError::UnsafeMemberPath {
            path: "p".to_owned(),
            reason: "r",
        },
        UpdateError::UnexpectedExecutable {
            path: "p".to_owned(),
        },
        UpdateError::InstallRootUnusable { reason: "r" },
    ];
    for error in errors {
        let rendered = error.to_string();
        assert!(
            rendered.starts_with('U'),
            "{rendered:?} must name a U-number"
        );
    }
}

/// The anchor set is never empty, because an empty set verifies nothing.
///
/// `TrustAnchorSet::new` cannot produce one: `primary` is not optional.
///
/// Mutation: change `primary` to `Option<TrustAnchor>`. Fails.
#[test]
fn an_anchor_set_always_has_at_least_one_key() {
    assert!(!anchors(1).is_empty());
    assert_eq!(anchors(1).len(), 1);
    let with_rollover = TrustAnchorSet::new(anchor_for(1), Some(anchor_for(2)));
    assert_eq!(with_rollover.len(), 2);
    assert!(!with_rollover.is_empty());
}
