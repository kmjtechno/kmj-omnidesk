# Remote branch audit

Audit of the 51 remote branches that `git branch -r --no-merged origin/main`
reports as unmerged, conducted before any deletion.

## Why "unmerged" is not the right question

Under squash merging, a branch's commits are never ancestors of `main`, so
`--no-merged` flags every historical branch forever. Neither
`git diff main...branch` nor `git cherry` is a reliable safety check here
either: a squash commit's patch-id matches no individual commit, and the
three-dot diff is taken against a merge base that predates the work.

The check that is reliable is content-based: compare every blob in the branch
tree against the same path in `main`. A branch is safe to delete when it
introduces no file `main` lacks and no file whose content differs from `main`'s.

## Result

- **1 branch** is a strict subset of `main` (safe by the strictest reading).
- **50 branches** share no branch-only files; they differ from `main` only in
  that they are *older* snapshots, plus files that main has since changed.
  For every one of these the content `main` holds for the shared paths is the
  successor of what the branch holds.
- **1 file exists on a branch and nowhere on `main`** (see below).

## The one at-risk item

`autopilot/m8-deterministic-resume` carries
`crates/omnidesk-core/tests/m8_weak_network_resume.rs`, an integration test
that main does not have.

`main` does have `crates/omnidesk-core/examples/m8_weak_network_resume.rs`,
but that is the *evidence generator* -- it prints a `PASS` JSON document. It
does not assert that a resumed transfer reproduces the original bytes or
rejects a corrupted chunk; it asserts that its own fixture runs. The example
is what CI greps for `m8_weak_network_resume":"PASS"`.

So the gap is specific: the CI gate proves the evidence generator executed, and
`collaboration.rs` has 5 in-module references to `TransferCheckpoint`, but an
end-to-end resume assertion that the reassembled stream matches the original and
that corruption is rejected does not exist on main.

## Recommendation

Do not delete `autopilot/m8-deterministic-resume` until its test has been
reviewed and either merged or consciously replaced.

The remaining 50 can be deleted once a reviewer agrees with the content
comparison above.
