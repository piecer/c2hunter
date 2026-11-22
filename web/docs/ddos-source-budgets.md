# DDoS source-snapshot admission budget audit

This boundary controls **report visibility and source authority**, not export
eligibility. It runs before the existing report validator and snapshot encoder.
It is a JSON-response boundary, not a sandbox for arbitrary same-process objects.
The report validator, export validators, controller schemas and UI owners are
unchanged.

## Projected job fields

Only `id`, `dataset_id`, `source_type`, `internal_networks`, and
`source.{sha256,link_types}` are read. Other job/source metadata is not traversed.

| Field | Supported producer / consumer contract | Admission allowance |
| --- | --- | --- |
| `id`, `dataset_id` | `jobs.build_job` generates UUIDs; upload dataset IDs are `pcap:` plus SHA-256; reference/export consumers support 200-character IDs | Aggregate includes two 200-code-point strings, conservatively 400 UTF-16 units each |
| `source_type` | Bounded source-kind enum, including `PCAP_UPLOAD` | 32 units in aggregate |
| `internal_networks` | Both `AnalysisJobCreate` and `PcapAnalysisJobCreate`: 1–256 unique normalized CIDRs, raw member length at most 64 Python code points | **256 only at this exact projected path**; normalization may add `/128` (4 code points), with at most 2 UTF-16 units per code point |
| `source.sha256` | Upload SHA-256 hexadecimal digest | 64 units in aggregate |
| `source.link_types` | `pcap.parse_pcap` adds every packet link type, including unsupported decoders, to its sorted unique census. Classic PCAP masks to uint16; PCAPNG IDBs read uint16 | **65,536 only at this exact projected path**, not one, 32, 100 or 256 |
| Object keys | Fixed projection keys, total 62 characters | 128 units in aggregate |

The source character allowance is
`256*(64+4)*2 + 2*200*2 + 64 + 32 + 128 = 35,840` UTF-16 units.
The complete supported source needs at most 65,807 visited nodes (keys count as
nodes); the existing 100,000-node ceiling is retained. Source shape depth is 3,
and object arity is at most 5. Existing 16-depth / 64-key ceilings remain.
Optional absence, including the entire job/source, remains accepted; this meter
does not add new semantic requirements or enforce export-specific ID eligibility.

**Important dependency behavior:** `ipaddress` accepts scoped IPv6. A 64-code-point
raw `fe80::1%...` normalizes to 68 code points; non-BMP scope characters make the
fixture 124 UTF-16 units. Therefore neither `256*43` (ordinary longest IPv6 CIDR)
nor `256*64` is a sufficient general source character budget. The schema is not
changed to prohibit this supported input. The synchronous upload query separately
limits its comma-separated text to 10,000 characters; staged JSON admission uses
the full schema. Browser witnesses stay within the synchronous query limit;
long/scoped boundary composition witnesses explicitly exercise schema normalization.

## Projected report fields

The source meter keeps its 100-item **report** array ceiling. The unchanged
semantic validator applies the smaller field-specific limits below. No report
array inherits either source-array exception.

| Shape / fields | Maximum |
| --- | --- |
| Root fields | 12, including optional/version-specific `normal_reference` |
| `findings` | 100 |
| `recommendations`, `warnings`, `limitations` | 18, 16, 8 |
| `summary` | 16 scalar fields; timestamps at most 32 units |
| Finding | 18 keys; deterministic ID 21, target IP at most 45, timestamps 32 |
| `metrics` | at most 40 keys; closed scalar fields or `component_types` array of 8 |
| Finding evidence, uncertainty, recommendation code arrays | 8 each |
| Classification | 6 keys; evidence 17 scalar keys; 3 axes, each 4 keys |
| Axis supporting / counter / unknown codes | at most 1 / 1 / 4 respectively, as constructed by `validV3Classification` |
| `common_patterns` | 8; each 5 keys, 16 values of at most 128 UTF-16 units |
| `signature_candidates` | 4; at most 13 keys including evaluation |
| Signature source/destination ports, size range, payload hashes, false-positive codes | 16 / 16 / 2 / 8 (64 hex each) / 4 |
| Evaluation | 10 keys; predicate 8, normal 3, each match result 15 |
| Predicate ports, TCP flags, length, protocol fields | 16 each port array; 4 / 3 / 1 keys |
| Match-result evidence references | 8, each at most 68 units; digest 64 |
| Normal reference | 7 keys; job/dataset IDs 200 each, selected-by 128, selected-at 64, digest 64 |
| Approval, exclusion, invalidation, export-target arrays | 3 / 2 / 2 / 1 fixed strings |

Authorities: `ddosReportContract.ts`, `ddosSignatures.ts`, `ddosEvidence.ts`,
`ddosReportTime.ts`; producer `ddos_attack.py` and `ddos_signatures.py`.
The producer additionally limits each evaluation to 8,192 encoded bytes and its
signature publication to 1 MiB. Those producer-only reductions are **not** used
to reject the broader established decoder shapes. Legacy coercion paths and
version-specific optional absence are not replaced by a new closed schema.

### Aggregate derivation

A visited node is a value/container or object key; array indices are not charged
as keys (and are not materialized by this walker).

* Finding core: `1+2*18 + 2*2 + 2*40+8 + 3*8 +
  (2*6+2*17+2*3+3*(2*4+1+1+4)) = 247` nodes.
* Each pattern: `1+2*5+16 = 27` nodes.
* Each evaluation adds 188 nodes:
  `2*10+2*8+2*16+2*4+2*3+2*1+2*(2*15+8)+2*3+2*7+3+2+2+1`.
* Each signature: `1+2*13+2*16+2+8+4+188 = 261` nodes.
* Root-only content (12 keys, summary, 18 recommendations, warning/limitation
  lists and reference) is below 1,024 nodes, including its long-reference values.
* Whole-report ceiling: `1024+100*(247+8*27+4*261) = 151,724` nodes.

For characters, core scalar/code/key strings fit 64 units, pattern keys fit 32,
and its ID/type fit 32 each. An entire candidate fits 8,192 units independently
of the producer's encoded limit: the evaluation has at most 66 keys of at most
32 units, two sets of eight 68-unit references plus digests, bounded reference
strings, predicate strings, and eight fixed policy strings; together these are
below 5,000 units. Outer signature keys/strings/hashes/codes add below 1,400.
Root-only content fits 65,536 units (including the reference's longer strings).
Thus the conservative structural report ceiling is:

`65536 + 100*(247*64 + 8*(5*32+2*32+16*128) + 4*8192) = 6,740,736`.

These are additive upper envelopes, not assertions that every Cartesian maximum
is reachable simultaneously. They cover the decoder's combinations rather than
fitting one convenient producer sample. Maximum supported depth is below the
retained depth 16; the largest supported object is the 40-key metrics object,
below the retained 64-key ceiling. Previous accepted bounded legacy shapes are
not narrowed by the increased aggregate allowances.

### Characters versus encoded bytes

This preflight counts JavaScript UTF-16 units before serialization; it does not
allocate a UTF-8 copy of unchecked strings. JSON escaping costs at most six ASCII
bytes per UTF-16 unit (including controls and lone surrogates). Structural and
numeric serialization is independently bounded by node count; 32 bytes per node
is a conservative allowance for punctuation and finite Number spellings. The
snapshot therefore has a finite derived encoded upper bound, not an accidental
2 MiB export limit. Actual report semantics still reject malformed values.
Tests include 128-control-character pattern values to exercise escaping, scoped
non-BMP networks, and combined maximum report/source content. The source meter
preserves ordinary optional `undefined` values, as the predecessor did.

## Separate export decisions

`passiveSelection` still requires a single supported capture link type, IPv4 UDP,
and at most 32 IPv4 networks. Its 16 KiB source admission, JSON export's 2 MiB
report/source checks and 64 KiB output limit remain unchanged. A valid source can
therefore display its DDoS report, PCAP guidance and AI entry while a specific
export is refused. No export restriction authorizes hiding the entire report.

## Regression evidence design

* Real upload -> schema normalization -> parser/analysis -> public GET -> built
  App: 101 and 256 unique IPv4 and IPv6 networks, PCAP/AI entry accessibility,
  visible candidate detail, explicit BPF refusal and no automatic POST.
* Actual parser full uint16 link census; schema long ordinary IPv6 and scoped
  Unicode maxima composed with 200-character IDs and capture SHA.
* Actual 100-finding producer report plus explicitly labeled consumer-accepted
  maximum pattern/signature/reference combinations, including both node-heavy
  and escape-heavy variants. These synthetic combinations are not mislabeled
  as producer outputs.
* 257 networks / 65,537 links / 101 findings and excessive string/key/depth/node,
  nonfinite and null controls reject before semantic serialization.
* Existing report/source replacement, in-place changes, rendered ABA retirement,
  unchanged inline projection, unrelated metadata, maximum DOM, first-fold,
  pending-operation, modal/focus/reflow and wire-parity tests remain unchanged.
