# README launch assets

The README embeds `docs/assets/c2hunter-demo.gif` and keeps the same path after this update.

| Asset | Description |
| --- | --- |
| `docs/assets/c2hunter-demo.gif` | English-language, 1280 × 720, 37-frame, 21.1-second animated workflow demonstration |
| `docs/assets/c2hunter-demo-poster.png` | English-language poster/first scene for the demo |

## What is shown

Dashboard → Analysis history → Upload PCAP → upload/analysis progress → C2 candidate review → scored behavioral evidence → analyst verdict → external TI and MISP hand-off.

The example candidate `203.0.113.10` is a documentation-range address; the demo uses deterministic sample data, not production traffic.

## Source and limitations

Reconstructed from the React frontend and Playwright E2E fixture in commit `a1d17e7` (2026-11-09). This is a browser-rendered *illustrative reconstruction*, **not** a screen recording of a running C2Hunter controller. Some demo labels are translated into English, while the current production UI uses a mixture of English and Korean. Values and progress are illustrative and should not be interpreted as results from a real capture.

To create a fully authentic capture in the future, start the actual React application with deterministic API fixtures and record the Playwright browser session.
