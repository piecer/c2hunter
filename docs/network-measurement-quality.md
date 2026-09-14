# Supporting measurement qualification (STEP 6)

`network-supporting-measurements-v1` adds optional `metric_quality` to each
representative example's `measurements`. The measurement version and all existing
raw fields, source/exclusion counters, detector decisions, and limits are unchanged.
This is a capture-local observation contract, not a statistical confidence model.

## Coverage is not sample adequacy

`coverage_complete` retains its existing meaning: absence of the producer's
measurement tracking/gap/availability reasons. It does **not** assert enough RTT,
spacing or TTL samples. A complete-coverage flow can have one SYN/ACK RTT sample,
zero data/ACK samples and an ambiguous excluded candidate.

The additive closed shape is:

```json
{
  "metric_quality": {
    "observed_rtt_ms": {"status": "limited_samples", "reasons": ["SINGLE_SAMPLE", "HANDSHAKE_ONLY", "BIDIRECTIONAL_RTT_NOT_ESTABLISHED", "SELECTION_BIAS_POSSIBLE"]},
    "interarrival_variation_ms": {
      "a_to_b": {"status": "observed_samples", "reasons": []},
      "b_to_a": {"status": "limited_samples", "reasons": ["SINGLE_SAMPLE"]}
    },
    "ttl_observed": {
      "a_to_b": {"status": "observed_samples", "reasons": []},
      "b_to_a": {"status": "observed_samples", "reasons": []}
    }
  }
}
```

This exact shape is witnessed by `handshake_only` in the checked-in
`web/tests/fixtures/network-measurement-quality.json`. Counts are referenced from
existing same-key statistics/TTL objects, not duplicated in qualification:

| Status | Associated metric count | Meaning |
|---|---:|---|
| `unavailable` | 0 | No eligible samples; never measured zero |
| `limited_samples` | 1 | One observation cannot establish dispersion/stability/path characteristics |
| `observed_samples` | >= 2 | Observations exist; **representativeness is not established** |

The boundary at two only distinguishes whether dispersion has more than one
observation. It is not a sufficiency threshold, baseline comparison, normality
label or guarantee of independence. A zero dispersion with multiple samples is
preserved as an observation, not proof of stability. Current producer singleton
stddev remains null. Compatibility consumers also preserve an explicitly supplied
singleton stddev of zero, labeling it as a raw algebraic value without meaningful
evidence of dispersion or stability; no qualification is synthesized for it.

## Fixed reasons and existing evidence

Reasons have canonical order as listed here, no duplicates, and a hard maximum of
five entries (the current producer emits at most four for RTT and two per direction):

1. `NO_SAMPLES`: count zero, mutually exclusive with `SINGLE_SAMPLE`.
2. `SINGLE_SAMPLE`: count one.
3. `HANDSHAKE_ONLY`: RTT has SYN/ACK samples but no eligible data/ACK samples.
4. `BIDIRECTIONAL_RTT_NOT_ESTABLISHED`: RTT sample direction is not tracked. Applies
   to RTT only; bidirectional packet observations do not prove bidirectional RTT sampling.
5. `SELECTION_BIAS_POSSIBLE`: a relevant tracked exclusion or gap exists. RTT uses
   existing `ambiguous`, `nonpositive_time`, `nonexact_ack` counters plus tracked
   incomplete-packet, non-monotonic-clock and correlation-limit reasons. Directional
   spacing uses those gap reasons; directional TTL additionally uses its own missing
   count. These are possible selection effects, not measured loss rates.

The existing TCP eligibility path is unchanged: SYN retransmissions invalidate
handshake candidates; data retransmission/overlap/wrap ambiguity suppresses data RTT
(including subsequent matches for that tracked direction); exact single-segment ACK
matching is required. Gap/clock/cap handling preserves prior facts. No skipped-match
counts are fabricated for gaps/caps because those quantities are not tracked.
No observation-window timestamps are added: issue first/last timestamps describe
pattern events, not a measured RTT/spacing observation window. No baseline is supplied,
so neither RTT magnitude nor spacing dispersion supports a high-latency/congestion
classification. One or many TTL observations prove neither route changes nor exact hops.

## Consumers, compatibility and budgets

- Python producer owns the typed statuses/reasons. The controller validates the
  entire additive object and checks its exact consistency with actual metric counts,
  source counters, exclusions and gap flags before any byte-budget allocation.
- Web checks the same shape/status/reason/count relationships atomically, renders
  only closed local English/Korean labels and never reflects unknown qualification
  prose. Invalid-present qualification is rejected, not treated as a legacy report.
- Absent `metric_quality` stays absent in AI projection and appears as **Not provided /
  제공되지 않음** in measurement-capable saved reports. It never becomes sufficient.
  Reports predating the measurement version retain their existing no-measurements UI.
- All five entries are constant-size; there are no new counters, raw packet data,
  sample lists, timestamps, detector thresholds or tracking-limit increases. Existing
  controller counters retain nonnegative signed-64-bit bounds; the browser fails
  closed on counts outside JavaScript's exact safe-integer range.
- AI retains the existing exact 24,000-byte budget and minimum-facts-first allocation
  for the first 20 issues. Measurement plus qualification is one atomic optional
  unit: if it cannot fit it is omitted whole, with existing detail accounting.
  No partial quality removal, invented upgrade or deletion of minimum issue facts.
- Raw spacing and TTL statistics remain in typed measurement fields; analysis prose
  references those fields instead of duplicating their dictionaries. This preserves
  the existing high-cardinality publication byte bounds without dropping evidence.
- UI remains lazy, one detail owner, bounded to existing group/example limits.

## Reproducible evidence (no model or network calls)

`web/tests/network_report_fixture.py --quality-contract` serializes actual parsed
packet reports and their actual controller AI projections, with explicit legacy and
malformed mutations kept separate from producer witnesses. The frontend compares
these exact newline-terminated bytes to the checked-in fixture twice before testing
localized presentation and validation parity.

Witnesses include handshake-only plus excluded data RTT, eligible data RTT,
retransmission suppression, data without RTT, singleton directional spacing,
singleton/missing/IPv6 TTL, reversed clock, and correlation limit at/plus-one.
The analysis suite retains constant-space tests. Controller tests exercise all-20
minimum-fact preservation, exact byte boundaries, late malformed quality rejection
under budget pressure and legacy omission. These local tests do not establish
statistical representativeness, real model behavior or physical-browser accessibility.
