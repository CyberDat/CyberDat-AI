# Measurements (Windows 11, AMD Ryzen 9 9950X3D, Node 24.14.1, Playwright 1.49.1, PHP from the pinned WordPress image)

Both sides were measured on the same machine, alternating before/after, release-1 sandbox (`tests/tools-sandbox-server.py`):
before = `3cbc111` on port 18092, after = `aae21c0` on port 18091. Edge = `tests/log-anonymizer-browser.test.cjs` (CDP),
Firefox/WebKit = `tests/log-anonymizer-xbrowser.test.cjs`, the same 30 MB `mixed.log` file.

## LA, 30 MB file (seconds, two rounds)

| Browser | Before r1 / r2 | After r1 / r2 | Reference given by the owner |
|---|---|---|---|
| Chromium (Edge) | 2.5 / 2.5 | 2.5 / 2.5 | 13.2 |
| Firefox | 3.2 / 3.0 | 3.1 / 3.1 | 15.6 |
| WebKit | 22.8 / 22.8 | 22.8 / 23.1 | 115 |

The reference numbers come from a different (slower) environment; the ratio WebKit/Chromium is similar (~9×). On this
machine the change makes no measurable difference: the 30 MB file contains almost no combining marks.

## Engine only, inputs dense with combining marks (Node, median of 3, ms)

| Input | Before | After |
|---|---|---|
| trigger words followed by 30-mark runs, no terminator (15.8 M chars) | 286 | 565 |
| NFD names in all five forms (9.6 M chars) | 510 | 865 |

Slower because these lines now match and are masked; all quantifiers are bounded (`{0,63}`), time grows linearly.

## Browser regression (PASS counts, all exit 0)

| Tool | Edge | Firefox | WebKit |
|---|---|---|---|
| Log Anonymizer | 21 | 14 | 14 |
| Prompt Injection Detector | 21 | 13 | 13 |
| LotL Command Analyzer | 16 | 10 | 10 |
| MCP Security & Policy Checker | 20 | 11 | 11 |
| Look-behind notice (Edge, simulated) | 6/6 | — | — |
