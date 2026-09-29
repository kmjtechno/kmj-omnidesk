# M4 REALNET-60 v1

This contract defines the minimum credible real-network evidence campaign for M4.

## Matrix
Exactly 60 VALID runs are required: 10 each for T1 broadband/broadband, T2 broadband/CGNAT, T3 CGNAT/CGNAT, T4 restrictive network, T5 IPv4/IPv6, and T6 reconnect. INVALID attempts are preserved but never counted and require replacement.

## Acceptance
Direct-eligible T1-T5 runs form the overall denominator. Proven T4 direct blocking may be excluded only with independent CONTROL_PROBE or NETWORK_DIAGNOSTIC evidence. T5 may be excluded only when evidence proves no compatible address family. A failed implementation is never an exclusion.

Thresholds: overall >=80%; T1 >=90%; T2 >=80%; T3 >=60%; T5 >=80%. Successful direct connection latency uses nearest-rank P50 <=1500 ms and P95 <=5000 ms. T6 requires 10 reconnect-eligible samples, >=90% success, P50 <=2000 ms and P95 <=5000 ms. All valid failures must have explicit taxonomy codes. Security-critical false success, wrong-peer authentication, unauthorized sessions, or integrity failure after success have zero tolerance.

## Percentiles
Sort integer millisecond samples ascending. For p in (0,1], rank = ceil(p*n), value = samples[rank-1]. No interpolation.

## Evidence integrity
Every reference resolves to exactly one declared artifact. Paths must remain inside the package. Declared byte size and SHA-256 must match actual bytes. Aggregate and gate fields are derived outputs and must be independently recomputed.

Validator outcomes are VALID_M4_PASS, VALID_M4_FAIL, or INVALID_MANIFEST. M4 remains in progress until a real representative campaign produces VALID_M4_PASS; synthetic/local CI evidence cannot substitute for this campaign.
