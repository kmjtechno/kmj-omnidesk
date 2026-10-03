# M13 — Release Candidate Performance Matrix

`benchmarks/network-profiles.yaml` declares four rules for this milestone:

```yaml
rules:
  raw_results_required: true
  environment_metadata_required: true
  cherry_picking_forbidden: true
  comparative_claims_require_reproducible_comparable_tests: true
```

Until this work, all four were aspirational. Nothing read them, so a
published number could be a summary someone typed, from a machine nobody
recorded, replacing a worse run that was quietly deleted, compared against a
baseline from different hardware. `scripts/m13_matrix.py` makes each rule
falsifiable.

## What the tool does, and what it deliberately does not

It does not run a benchmark, produce a number, or decide whether a result is
good. It only decides whether a supplied measurement set is **admissible**.

That distinction is the point. A complete, honest, badly-performing matrix
passes every check here, and it should — the tool's job is to guarantee that
what gets published is what got measured. Anything it did beyond that would
be it deciding what to report, which is precisely the failure mode the rules
exist to prevent.

## The four rules, as enforced

**`raw_results_required`.** Every recorded run carries a SHA-256 of its raw
per-sample file, and `verify` re-hashes the file. Both a missing file and an
edited one are refused.

The edited case is the one worth having. An unhashed raw file is a summary
wearing a raw file's name. A *replaced* one is a measurement that was captured
honestly and then improved later — which is what cherry-picking looks like
when it is not done by deleting anything.

**`environment_metadata_required`.** A run without `machine_id`, `os_build`,
and `commit` is refused. A measurement without the machine it came from cannot
be compared to anything, so storing it only invites a later comparison that
cannot be justified.

**`cherry_picking_forbidden`.** The ledger is append-only and a `run_id` cannot
be recorded twice. This is the form the rule actually takes in practice: not
deleting a run, but re-running it and replacing the entry under a name a
reviewer has already seen. `verify` also re-checks for duplicates, so a
hand-edited ledger is caught too.

**`comparative_claims_require_reproducible_comparable_tests`.** `compare`
refuses any pair of runs that differ in `machine_id`, `os_build`, `commit`, or
`profile`.

`profile` earns its place specifically. Comparing `office_good` against
`severe` and reporting the difference is the easiest false claim this matrix
could produce, and it requires no dishonesty at all — only selecting the two
runs that produce the story.

## Usage

```bash
python3 scripts/m13_matrix.py init --root evidence/m13-rc1

python3 scripts/m13_matrix.py record \
  --root evidence/m13-rc1 \
  --run-id M13-office_good-R001 \
  --raw evidence/m13-rc1/raw/M13-office_good-R001.samples.jsonl \
  --environment evidence/m13-rc1/M13-office_good-R001.env.json \
  --metrics evidence/m13-rc1/M13-office_good-R001.metrics.json

python3 scripts/m13_matrix.py verify --root evidence/m13-rc1

python3 scripts/m13_matrix.py compare \
  --root evidence/m13-rc1 \
  --baseline M13-office_good-R001 \
  --candidate M13-office_good-R002
```

`verify` fails if any run is missing one of the ten metrics M13 requires. The
required set comes from `network-profiles.yaml`, not from whatever a run
happened to report — otherwise "the metric set" drifts down to whatever was
easiest to measure.

`compare` prints both sides of every metric. It deliberately renders no
verdict, delta, or percentage: whether 47 ms is better than 42 ms is a
judgement about a workload, not something a comparison tool can decide. A
tool that printed the delta would be an advertising tool.

## Verification

11 tests, each naming the single edit that would make it pass while the
property is broken. All 8 mutations were applied and every one was caught.

One test deserves naming: `test_a_comparable_comparison_reports_both_sides`
asserts that the baseline's number is still in the output. A comparison tool
that shows one side is an advertising tool, and that is a failure mode a
"compare" command invites by name.

The mutation harness initially reported all 8 as survivors. That was a bug in
the harness's name-matching, not in the tests — confirmed by running one
mutation by hand and watching the correct test fail. Worth recording because
the opposite conclusion, "the tests are weak", would have been the plausible
reading of the same output.

## What this does not deliver

**There is no matrix.** The tool makes a matrix checkable; it does not
produce one. Of the ten required metrics, one (`reconnect_time_ms`) is
currently emitted by an example; the other nine have no producer. A real
matrix needs measured runs across the declared profiles on more than one
machine.

**M13's status stays `pending`.** `full_matrix_complete` cannot honestly be
reported. What changed is that the moment a matrix does exist, the four rules
will be checked rather than asserted.

## Relationship to M4

M4's evidence collector (`scripts/m4_evidence.py`) governs one campaign:
60 real-network runs across six topologies. This governs repeated
release-candidate measurement across network profiles. They share the
append-only, hash-verified, no-synthetic-outcomes discipline and are
deliberately separate tools — M4's run-id grammar encodes its topology matrix,
which does not fit a benchmark sweep.