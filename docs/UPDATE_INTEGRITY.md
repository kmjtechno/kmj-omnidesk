# Update Integrity Design — Pre-alpha

This document is the design for the `update_integrity_design` deliverable of
M11. It specifies what must be true before an update can be applied, and what
must never be true.

It is a design, not an implementation. Nothing here describes shipping code.
Where a mechanism is named, it is because the design has to commit to
something checkable, not because that mechanism has been built.

## Why this exists

An update channel is the one place where OmniDesk asks a machine to run new
code with the user's privileges. Every other trust boundary in
[THREAT_MODEL.md](THREAT_MODEL.md) can fail into "the session is broken"; this
one fails into "the machine is now running the attacker's build."

The threat model already lists malicious update and downgrade as a primary
threat. This document turns that into requirements.

## What an attacker wants

Stated as goals, because each one implies a different check:

1. **Run their code.** Get an unsigned or self-signed build accepted.
2. **Run older code.** Downgrade to a version with a known vulnerability.
3. **Run someone else's build.** Substitute a legitimately signed build
   intended for a different channel, customer, or architecture.
4. **Split the channel.** Serve build *N* to some machines and *N+1* to
   others, then exploit the ones left behind.
5. **Subvert verification.** Disable, patch out, or bypass the check itself.
6. **Roll back silently.** Restore an old build after a security fix,
   presenting it as a normal update.

Goals 4 and 5 are the ones that a naive "check the signature" design misses.

## Required properties

These are release-blocking. Each is phrased so a test could refute it.

### U1 — Artifacts are signed, and unsigned artifacts never execute

Every distributed artifact carries a detached signature over its exact bytes.
The client verifies before extracting, before writing, and before executing.
A verification failure is terminal: no fallback, no retry from the same source
treated as "probably fine."

Signature verification happens in code that does not also parse, extract, or
apply the update. A parser reachable before verification is a parser an
attacker can crash or exploit with unauthenticated bytes.

### U2 — Signatures are anchored to a key compiled into the client

The trust anchor is a public key baked into the shipped binary. Not
downloaded, not read from the filesystem, not from a registry value, not from
the update server. A client that fetches its own trust anchor can be told to
trust anything.

Key rotation is a build-time change with an overlap window: the shipped binary
carries both the old and new key, and a later build drops the old one. An
out-of-band emergency rotation requires a binary that already trusts the new
key. That limit is real and is accepted rather than papered over with a
server-side override, because a server-side override is U6.

### U3 — Downgrade to a vulnerable version is refused

Every build carries a monotonically increasing version. An update is rejected
if it is not strictly newer than the running build.

Monotonic, not date-based. A build number that can be reused, or a clock the
client trusts, reintroduces downgrade.

This is stricter than it first appears: it also forbids reinstalling an
identical build, and forbids a legitimate emergency rollback to a *newer*
build id that ships older code. The rule is on the identifier, and the
identifier is the thing that has to be defended.

### U4 — Signature alone is not sufficient; the release manifest is signed

The artifact signature proves *someone with the release key signed these
bytes*. It does not prove that signing was authorized.

A signed manifest, also under U2's anchor, states per artifact:

- version;
- target platform and architecture;
- release channel;
- SHA-256 of the artifact;
- minimum permitted client version.

The client checks the artifact hash against the manifest, and the manifest
against its expectations, before applying anything.

Without the manifest, a compromised release-signing host can produce a
perfectly valid signature over a malicious build, and U1 passes while the
machine is still compromised.

### U5 — Channels are segregated and the client pins its channel

Channel (stable, beta) is part of the signed manifest. A stable client will not
apply a beta build, and a beta client will not silently become stable.

Cross-channel leakage is how U4's "someone else's build" is delivered to a
machine that will accept it.

### U6 — There is no server-side switch that disables verification

No configuration, environment variable, registry key, command-line flag, or
remote setting may lower or bypass update verification.

Every such switch is an attacker goal (U5, sub-goal 5) with a documented name.
If a support workflow needs one, the answer is a new signed build.

The same applies to the client refusing to start or refusing to run: a client
that cannot run without phoning home to check whether it may run has moved the
trust decision to the server and reintroduces the problem.

### U7 — The update path cannot write outside its intended location

The installer writes to a known set of paths. Path traversal in an archive
member (`../../...`) is rejected before extraction, not sanitised after.

### U8 — Uninstall leaves no updater able to run

See [uninstall cleanup](#update-and-uninstall-cleanup) below.

### U9 — Update metadata is fetched over an authenticated channel

Metadata is served over HTTPS with a pinned trust chain equivalent to U2's, or
over a channel whose authenticity the artifact signature already provides.
Metadata is treated as untrusted input regardless: a hostile server must not be
able to cause anything worse than "no update available."

Because U1-U4 make metadata advisory, a fully hostile metadata server results
in the client staying on its current build. That is the intended failure.

## What is deliberately not claimed

- This design does not name a specific signature algorithm or key format.
  Choosing between them is a decision with its own review, and choosing badly
  is expensive to undo.
- It does not describe a transparency or revocation service. Such a service is
  useful for the *browser* problem; for a desktop client whose trust anchor is
  compiled in, revocation is handled by shipping a new build. Assuming a
  revocation endpoint would be assuming a channel that must itself be trusted.
- It does not claim the current pre-alpha build implements any of this as a
  shipping updater. It does not. There is no updater, no installer, and no
  release-signing service. What exists is the verification core described under
  [What is implemented](#what-is-implemented) below.

## What is implemented

`crates/omnidesk-core/src/update_path.rs` implements the part of this design
that can be built and refuted without an installer, a signing service, or a
network. It is M12's `safe_update_path` deliverable.

The API is shaped as a chain of types where each step consumes the previous
step's output:

```text
TrustAnchor -> VerifiedArtifact -> VerifiedManifest -> StagedUpdate -> InstallPlan
```

There is no way to name an `InstallPlan` without a `VerifiedArtifact`, and no
way to produce a `VerifiedArtifact` without a signature verified against a
compiled-in key. Skipping a check is not a branch that can be flipped; it is
unrepresentable.

| Property | Where | State |
|---|---|---|
| U1 | `TrustAnchor::verify`, `UnverifiedManifest::verify_and_parse` | Implemented and tested |
| U2 | `TrustAnchor`, `TrustAnchorSet` | Implemented and tested |
| U3 | `StagedUpdate::check_client_floor` | Implemented and tested |
| U4 | `StagedUpdate::stage` | Implemented and tested |
| U5 | `StagedUpdate::stage` | Implemented and tested |
| U6 | whole module | Enforced by construction and by a source-level test |
| U7 | `ArchiveMember::validate`, `InstallPlan::target_paths` | Implemented and tested |
| U8 | `uninstall.rs`: `UninstallPlan::confirm_clean` | Implemented and tested |
| U9 | `verify_and_parse` | Implemented and tested |

Three properties constrain the shape of the code rather than a branch in it:

- **U6 has no configuration surface.** Nothing in the module reads an
  environment variable, a config file, a registry value, or a command-line
  flag. `EXPECTED_CHANNEL` and `EXPECTED_PLATFORM` are constants, so a
  user-selectable channel is impossible rather than merely discouraged. A test
  reads the module's own source and fails if it names any configuration source.
- **U2's anchor has no setter.** `TrustAnchor` is not `Deserialize`, has no
  public field, and no constructor from bytes. Rotation is a new build carrying
  `TrustAnchorSet::new(primary, Some(rollover))`.
- **U1 parses nothing before verifying.** `UnverifiedManifest` holds opaque
  bytes; `ManifestBody::parse` is called only after a signature check returns
  `Ok`. A parser reachable before verification is a parser an attacker can
  attack with unauthenticated bytes.

### Not implemented, and why

- **Extraction.** `StagedUpdate` holds a validated member list, not extracted
  files. Doing real extraction needs an archive parser, and U1 forbids a parser
  reachable before verification. U7's traversal check runs over member *names*,
  which is where it has to run regardless.
- **The shipping signature algorithm.** `TrustAnchor` wraps
  `ed25519-dalek::VerifyingKey` because that crate is already a dependency and
  is a sound implementation. That is a starting point, not the design's answer
  to the open question above, and it is not a claim that the choice is made.
- **U1's end-to-end path.** Verifying a signature is implemented; running a real
  installer that verifies one, writes the files, and rolls back on failure is
  not. `signature_verification_pass` cannot honestly be reported until it is.

## Update and uninstall cleanup

`uninstall_cleanup` is M12, but it is inseparable from this document: an
updater that survives its own uninstall is a persistence mechanism.

### U8 — after uninstall, nothing remains that can install or launch

Specifically:

- the scheduled task or service that checks for updates is removed;
- no auto-start entry for the updater or the application remains;
- no credentials, cached entitlements, or tokens remain in app-owned paths;
- install and update directories are removed;
- files outside the declared install root are left alone — an installer that
  writes outside its own root cannot clean up after itself, and deleting
  outside that root to compensate risks destroying user data.

The last point is a real constraint on installer design, not just a cleanup
step. It means the install root has to be declared and respected from the
first build, before uninstall cleanup exists.

#### What is implemented for U8

`crates/omnidesk-core/src/uninstall.rs`. Until this, U8 was the one property
in this document specified only in prose — the sentence saying an updater that
survives is a persistence mechanism, with nothing behind it.

The model is in-memory and takes its "what is still present" answer as input,
rather than touching the filesystem. That is a limitation worth stating plainly:
**this does not delete anything.** It decides whether a claimed removal is
complete, and refuses to certify one that is not. A caller that passes an empty
`surviving` list without enumerating the machine will be told the uninstall is
clean, and nothing here can detect that.

Three properties are enforced, and each fails closed:

**Containment is segment-boundary, not string-prefix.** `/opt/kmj-backup` starts
with `/opt/kmj` and is a different directory. A prefix check that treated it as
inside the root would make the uninstaller delete a neighbour's files, which is
the failure U8's last bullet exists to prevent. `normalize` collapses `.` but
deliberately does **not** resolve `..`: resolving it would turn
`/opt/kmj/../../etc/passwd` into `/etc/passwd`, which is refused — but refused
by accident, and a traversal that lands back inside the root would then be
accepted on a technicality.

**The residue check covers paths the plan never recorded.** Checking only what
the installer wrote would miss a scheduled task or autostart entry the product
created and forgot. `confirm_clean` therefore examines everything reported as
surviving, and reports outside-the-root survival as a failure rather than as
"uninstalled with warnings" — an installer that wrote outside its own root is a
design bug, and reporting it as a warning is how it becomes permanent.

**User data is reported, never removed.** `OwnedPath::user_owned` marks a path
the uninstaller keeps. It is reported separately from residue, because "it
survived" and "you were supposed to remove it" are different failures and
conflating them hides the first behind the second.

29 tests, each naming the single edit that would make it pass while the property
is broken. All 28 mutations were applied and caught.

Two of those mutations are worth recording, because both were initially
reported as either caught or structural when they were something else:

- A mutation collapsing all four `ResidueKind` names to one string **survived**.
  The test compared the four names to each other, which catches a collapse to
  fewer than four but not a rename to a different unique string — which is the
  edit a careless rename actually makes. The test now compares each name to its
  exact expected string.
- The mutation harness itself was wrong twice. It reported 4 mutations as
  "apply failed" when it was matching line-by-line and `rustfmt` had wrapped the
  patterns across two lines, so they were never actually tested; and one run
  reported a compile error as a caught mutation when the replacement text
  referenced a helper that did not exist. Both were found by running a mutation
  by hand, which is the only reason they were found.

One clause in `is_plausible_root` — comparing the normalized root against `"/"`
— was removed rather than kept. A mutation dropping it survived with every test
green, because the length check refuses the same inputs. That is a clause that
cannot change an answer, and a security check that reads as if it does is worse
than one that does not.

#### What U8 still does not have

**No filesystem access, so no deletion and no discovery.** Everything this
module checks was handed to it. A real uninstaller has to enumerate a machine
to know what survived — scanning the autostart directories, the task scheduler,
the credential store — and that enumeration is the part that actually does the
work and can still get it wrong. This module verifies an answer; it does not
produce one.

**No platform paths.** `ResidueKind` names categories, not locations. On Windows
the autostart entries are registry values and startup-folder shortcuts; on Linux
they are XDG autostart `.desktop` files; on macOS they are launchd plists. None
of that is here, and the residue a platform leaks is exactly the kind this
cannot see.

**M12's status does not change.** `uninstall_cleanup` needs a real installer to
run a real uninstall against, and `signature_verification_pass` needs
production signing keys. Both are still unmet.

## Verification, before release

Corresponding to U1-U9, an update-integrity test must demonstrate:

| Property | Test |
|---|---|
| U1 | Unsigned and tampered artifacts are refused, on every platform |
| U2 | A trust anchor read from disk is ignored in favour of the compiled-in one |
| U3 | Older and equal versions are refused |
| U4 | A correctly signed artifact absent from the manifest is refused |
| U5 | A stable client refuses a beta manifest and a beta artifact |
| U6 | No configuration can disable verification |
| U7 | A traversing archive member is rejected pre-extraction |
| U8 | After uninstall, no updater task, service, or autostart entry remains |

A property with no test above is not met, however convincing the design
sounds. The same rule the M8 resume gate violated applies here: a check that
does not assert cannot fail, and a check that cannot fail is not a gate.

Of the eight, U1, U2, U3, U4, U5, U7, and U9 have 42 tests in
`update_path.rs`, and U8 has 29 in `uninstall.rs`. U6 is tested by a test that
reads the module's own source and fails if it names a configuration source,
which is the closest honest test for a property that is enforced by absence.

U8 was previously the one property here with no code behind it at all. Its row
above described a required test that did not exist, which the "a property with
no test above is not met" rule was written to prevent and which had been
violated in the document's own table.

Every one of those tests was checked to fail when the behaviour it covers is
removed. One of them, `u1_an_unparsable_unsigned_manifest_is_refused_on_signature_not_parse`,
was written specifically because the first version of the manifest parser
rejected a manifest it should have accepted: an unknown member containing a
nested object was split at its first `}`, and the fields inside it came back
looking like top-level fields. The ordering test was what distinguished "the
parser is wrong" from "verification ran first".

## Open questions

Carried forward rather than guessed at:

- Signature algorithm and key format (see above).
- Emergency rotation when no shipped binary trusts the new key.
- Whether channel pin is user-selectable. It must not be: U5 is a
  release-blocking property, and a user-selectable channel is U6 by another
  name. Recording the tension rather than resolving it silently.