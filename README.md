# Two-party ECDSA

How costly is threshold ECDSA? This repository holds our implementation of a
two-party ECDSA signing protocol and the benchmarks that measure what splitting
the key costs compared to normal single-device signing.

HSG Bachelor project, supervised by Prof. Katerina Mitrokotsa and Nan Cheng.

## Status

| Part | State |
|---|---|
| Single-device ECDSA baseline | done, tested against libsecp256k1 |
| Additive secret sharing | done |
| Channel between the parties, echo benchmark | done |
| Docker setup with optional network delay | written, to be tried on a machine with Docker |
| Pure-Python ECDSA, any curve (`ec.py`, `ecdsa_pure.py`) | done, checked against libsecp256k1 |
| Trace recorder and protocol visualizer (`trace.py`, `web/`) | done (stage 1) |
| Paillier encryption (`paillier.py`) | done |
| MtA (`mta.py`) | done, as described by the supervisors (semi-honest, no range proofs) |
| Two-party signing (`protocol.py`) | done, Gennaro & Goldfeder 2018 simplified for two parties, checked against libsecp256k1 |
| Experiment: Bob leaves out β' in MtA, Alice learns his key share | done in code and tests |
| Benchmark of two-party signing | `--task sign` with any combination of building blocks, `--task matrix` for all of them |
| Building blocks: libsecp256k1 in the protocol, gmpy2, Paillier CRT decryption and encryption, precomputed r^N, 3072-bit key, binary messages (`config.py`) | done, every variant tested to give a valid signature |
| Building blocks: MtA reuse, batched messages | done |
| Two laptops on the same Wi-Fi: pairing code, in the terminal demo and in the web lab | done, tested on one machine so far |
| Interface with one row per building block, study and benchmark mode (`python -m twoparty ui`) | done |
| Pairing in the web lab: one laptop is Bob, the other joins with the 4-digit code | done |
| Terminal demo: Alice, Bob and an observer, study mode, event log (`demo.py`) | done |
| Demo UI for MtA and two-party signing, experiment in the visualizer | open |

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

`pytest` also runs the JavaScript check in `tests/js/` if Node.js is installed
(`brew install node`); without Node that one test is skipped.

## Building blocks

Every row of the table "Building blocks and their implementations" on our
protocol sheet is one field of `Config` in `src/twoparty/config.py`. `Config()`
is the protocol as we first built it; `--set row=variant` swaps one block.

| Row (`--set`) | Variants (first = original) |
|---|---|
| `curve` | `pure`, `libsecp256k1` |
| `bignum` | `int`, `gmpy2` (`pip install -e ".[fast]"`) |
| `paillier_dec` | `naive`, `crt` |
| `paillier_enc` | `naive`, `crt` (Alice only, Bob has no p and q), `precomputed` (r^N offline) |
| `paillier_bits` | `2048`, `3072` |
| `wire` | `json`, `binary` |
| `mask` | `true`, `false` (the experiment without β′) |

```bash
python -m twoparty --task matrix --rounds 20          # starts its own Bob on localhost
python -m twoparty --task matrix --peer HOST:5050     # against a Bob elsewhere (Docker, second device)
```

The matrix runs the original, every variant on its own, and all speed-ups
together, and writes one CSV row each to `benchmark/results/`: signing time
(mean, median, p95), signatures per second, verification time, messages and
bytes per signature, and setup and offline time apart.

## Two laptops on the same Wi-Fi

No IP addresses to type: one laptop hosts and prints a 4-digit pairing code,
the other joins with it (`src/twoparty/lan.py`, UDP broadcast on port 5051).

**Demo** (each person sees their own side, step by step):
```bash
python -m twoparty lan --name Bruno          # laptop 1: asks mode/pace/experiment, prints e.g. "Pairing code: 4821"
python -m twoparty lan --code 4821           # laptop 2: finds laptop 1, plays Alice
```
Laptop 1 runs the observer as a quiet relay plus Bob; `--as alice` swaps the
roles, `--show-network` also prints the network view there. Pace `all` means
Enter on both laptops. The three-terminal setup with `--hub` still works.

**Benchmark** between two laptops:
```bash
python -m twoparty --role bob --lan                          # laptop 1, prints a code
python -m twoparty --task matrix --lan --code 4821 --label wifi   # laptop 2
```

If nothing is found, the program says what to check:
- Both laptops must be on the same network, without VPN.
- macOS asks once whether Python may accept incoming connections: click Allow.
- University and guest networks (eduroam) often block traffic between devices. Use a phone hotspot instead.
- As a fallback, type the address the host printed (`--hub IP:5050` or `--peer IP:5050`).

The code only prevents connecting to the wrong laptop. It is not a password: anyone on the network can read the beacons.

### In the web lab

Both run `python -m twoparty ui`. Under "Partner on the same Wi-Fi", one
picks **be Bob for a partner** and reads out the 4-digit code; the other picks
**join a partner as Alice** and types it. From then on study mode and benchmark
mode on Alice's laptop use the partner as Bob. Bob's page lists every session
and the steps Bob computed in the last signature, so both screens show their
own half. In study mode Alice's page shows both halves, put in the order the
messages force (the two clocks are not compared).

## Building-block lab (web interface)

```bash
python -m twoparty ui            # opens http://127.0.0.1:8765
python -m twoparty ui --port 9000 --no-browser
```

One table row per building block (taken from `config.ROWS`, so new rows show
up by themselves; planned variants are listed but cannot be chosen).

- **Study mode** runs one real signature (Alice and Bob over a local socket)
  and lists every step and every message: who computes, which building blocks
  are at work (their rows are highlighted), the time spent and all values.
  Back/Next or the arrow keys. The toy curve keeps the numbers small; the
  experiment without β′ shows Alice recovering Bob's key share.
- **Benchmark mode** runs N signatures per configuration: the one chosen,
  every variant alone, or original against all speed-ups. Results arrive row
  by row (signatures per second, signing mean/median/p95, verification,
  messages and bytes per signature, offline time) with a bar chart, and are
  saved as `benchmark/results/lab-<time>.csv`. "Bob at host:port" points the
  benchmark at a Bob elsewhere, e.g. on a second laptop
  (`python -m twoparty --role bob --listen 0.0.0.0:5050`).

Standard library only (`ui_server.py`, `lab.py`, `web/lab/`), no build step.

## Run it

The code is the same everywhere. Only the address of the other party changes.

Not port 5000 on macOS: AirPlay Receiver listens there, accepts the
connection and never answers, so Alice just hangs. The examples use 5050.

**Same machine**
```bash
python -m twoparty --role bob   --listen 127.0.0.1:5050        # terminal 1
python -m twoparty --role alice --peer   127.0.0.1:5050 --label local   # terminal 2
```

**Docker**
```bash
docker compose up -d bob
docker compose run --rm alice
```

**Docker with delay**
```bash
docker compose up -d bob
docker compose exec bob tc qdisc replace dev eth0 root netem delay 50ms
docker compose run --rm alice            # label it, e.g. add: --label docker-50ms
docker compose exec bob tc qdisc del dev eth0 root
```

**Two devices** (same network, port 5050 open)
```bash
python -m twoparty --role bob   --listen 0.0.0.0:5050                   # laptop B
python -m twoparty --role alice --peer   <address of B>:5050 --label devices-wifi   # laptop A
```

**Single-device baseline** (no network)
```bash
python -m twoparty --task baseline --rounds 200
```

**Two-party signing** (Bob as above; Alice picks the curve, Bob follows)
```bash
python -m twoparty --role alice --peer 127.0.0.1:5050 --task sign --rounds 20 --label local
python -m twoparty --role alice --peer 127.0.0.1:5050 --task sign --curve toy --rounds 200
```
`setup_ms` is the one-time setup (Paillier keygen, key shares), timed apart
from the signatures. On secp256k1 one signature takes about 2.3 s, almost all
of it Paillier with a 2048-bit N in pure Python.

**Watch it step by step** (three terminals; the observer starts first and asks
for mode, pace and the experiment)
```bash
python -m twoparty.demo observer --listen 127.0.0.1:5050                          # terminal 1
python -m twoparty.demo bob      --hub    127.0.0.1:5050                          # terminal 2
python -m twoparty.demo alice    --hub    127.0.0.1:5050                          # terminal 3
```
The observer is the network: Alice and Bob talk only through it. Alice and Bob
print every value they compute, the observer only what goes over the wire.
Modes: `study` (small numbers, every formula filled in, to calculate along),
`toy` (as advised) and `secp256k1`. Pace: Enter in all terminals, Enter only in
the observer, or run through. `--events FILE` writes all three views as JSON
lines, the base for a UI later.

Results are printed as one JSON line. With `--out benchmark/results/results.csv`
they are also appended to a CSV file. Always set `--label` so runs can be told apart,
and note the network used (Wi-Fi, cable, hotspot).

## Protocol visualizer

`web/` is a static page that walks through key generation, key sharing,
signing, verification and a nonce reuse attack, one step at a time, with the
real numbers from our Python code. No build step, only HTML, CSS and JS modules.

```bash
python -m twoparty.trace --out web/data/             # traces for both curves
python -m twoparty.trace --vectors tests/vectors.json  # test cases for the JS check
python -m http.server -d web 8000                    # then open http://localhost:8000
```

Run both trace commands again after changing a step; a test fails if the
committed JSON is out of date. Options: `--curve toy|secp256k1`, `--message`,
`--seed`, and `--d`, `--d1`, `--k`, `--e2` to set values by hand. Opening
`index.html` directly as a file does not work, because browsers block loading
the JSON from `file://`. On GitHub Pages, publish the `web/` folder.

How the numbers get to the page:

- Python (`trace.py`) runs every step and writes the inputs, formula and result
  of each one to `web/data/<curve>.json`. Unless the user edits something, the
  page shows only these numbers.
- On the toy curve the user can change d, d₁, k and the hashes. The page then
  recomputes with `web/js/steps.js`, a BigInt copy of the same step registry,
  and says so. `tests/js/vectors.test.mjs` checks that copy against Python
  step by step on 39 cases (both curves, including error cases).
- MtA and two-party signing are listed as planned steps. To add one, give it a
  compute function in `STEPS` (`trace.py`) and in `COMPUTE` (`web/js/steps.js`)
  under the same id, then regenerate the JSON.

**Toy curve.** y² = x³ + 7 over p = 349 (same equation as secp256k1). The group
has n = 313 points, a prime, so every point except infinity generates it.
G = (2, 109), the point with the smallest x. Found with
`python scripts/find_toy_curve.py`; the only other candidate below 400 is
p = 397, where n = p, a weak ("anomalous") curve.

**Choices.** The hash is e = SHA-256(m) mod n, as on our slides and in
`ecdsa_baseline.py` (the standard keeps the leftmost bits instead; same result
on secp256k1, different on the toy curve). Low-s is applied on both curves.
Demo values are fixed (toy) or come from a seeded RNG (secp256k1), so they are
public. The benchmark keeps using libsecp256k1; the pure-Python ECDSA is only
for the trace and is much slower.

## Layout

```
src/twoparty/
  curve.py           secp256k1 helpers (libsecp256k1 via coincurve)
  ecdsa_baseline.py  single-device ECDSA with the formulas from our slides
  ec.py              pure-Python curve arithmetic, secp256k1 and the toy curve
  ecdsa_pure.py      pure-Python ECDSA that exposes every intermediate value
  trace.py           step registry and trace recorder (JSON for the web page)
  sharing.py         additive secret sharing
  net.py             message channel (JSON, length-prefixed), counts messages and bytes
  paillier.py        Paillier encryption (compute on encrypted numbers)
  mta.py             multiplicative-to-additive conversion with Paillier
  protocol.py        two-party signing: setup, sign_alice, sign_bob
  bench.py           timing helpers, echo, baseline and two-party signing benchmarks
  demo.py            Alice, Bob and a network observer in separate terminals, step by step
tests/               pytest; tests/js: JavaScript check against tests/vectors.json
scripts/             find_toy_curve.py, uml.py
web/                 protocol visualizer (index.html, css/, js/, data/)
benchmark/results/   measurement output
docs/sessions/       one log per programming session: what we did, what broke, why these tests
docs/uml/            UML before/after each session (python scripts/uml.py --before <ref>)
docs/img/            screenshots
```

## Notes

- Educational code. Not constant-time and not side-channel safe, never use it
  with real funds. This holds especially for the pure-Python ECDSA and the page.
- Use test keys only. Do not commit keys or `.env` files.
