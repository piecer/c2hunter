# HIGH_VOLUME_TCP_SESSION policy backtest

Dataset: curated deterministic policy fixture; not historical production traffic

| Policy | Recall | False-positive rate | Analyst queue visible |
|---|---:|---:|---:|
| cap-20 | 0.0000 | 0.0000 | 0 |
| strong-evidence-cap-40 | 0.5000 | 0.0000 | 1 |
| fixed-penalty-25 | 1.0000 | 1.0000 | 4 |

The fixture demonstrates policy trade-offs only. It does not authorize changing the production default without representative historical labels.
