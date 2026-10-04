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

**There is no matrix.** `crates/omnidesk-core/examples/rc_matrix_benchmark.rs`
emits six of the ten required metrics across all four declared profiles and
runs in CI. It emits **four as `null`, deliberately**:

| Metric | Why not measured |
|---|---|
| `bandwidth_kbps` | The only throughput reachable on loopback is a CPU memory copy. It reports in the gigabits per second and would be read as a network result. |
| `cpu_percent`, `gpu_percent`, `ram_mb` | Need measurement of a live process on the target machine. A benchmark binary is not one. |

So the artifact is refused by `m13_matrix.py verify`, and that refusal is the
gate working. The CI step asserts the incompleteness rather than the
completeness:

```
assert d["metrics_emitted"] < d["metrics_required_by_m13"]
assert "bandwidth_kbps" not in row
```

If someone later makes those numbers appear, CI fails. That is the point of
gating an incomplete matrix: the failure mode being prevented is a filled-in
figure, not a missing one.

**Three of the six measured figures carry caveats**, stated in the output
rather than in this document:

- `direct_connect_success_rate` is a loopback UDP establishment, not a NAT
  traversal. It says nothing about Internet reachability and must never be
  published as a success rate.
- `interactive_latency_ms` covers capture conversion and queueing inside this
  process, not compositing or display. It is a floor.
- `visual_quality_metric` is a position on the quality ladder, not a
  perceptual score. There is no reference here to measure quality against, so
  naming it a metric at all is a stretch the output acknowledges.

`link_declared_bandwidth_kbps` is reported under that name rather than
`bandwidth_kbps` precisely because it is the profile's *input*. Presenting a
configured value under a measured-metric name is the same mistake in a
smaller package.

**M13's status stays `pending`.** `full_matrix_complete` cannot honestly be
reported. Producing the four missing metrics needs a shaped network link and
per-machine resource sampling, and the matrix needs runs across more than one
machine. What changed is that the moment a matrix does exist, the four rules
will be checked rather than asserted.

## Relationship to M4

M4's evidence collector (`scripts/m4_evidence.py`) governs one campaign:
60 real-network runs across six topologies. This governs repeated
release-candidate measurement across network profiles. They share the
append-only, hash-verified, no-synthetic-outcomes discipline and are
deliberately separate tools — M4's run-id grammar encodes its topology matrix,
which does not fit a benchmark sweep.