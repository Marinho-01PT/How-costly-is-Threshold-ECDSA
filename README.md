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
| MtA (`mta.py`) | open, waiting for the supervisors' description |
| Two-party signing (`protocol.py`) | open |
| Demo UI, experiment (switch off a safety measure) | open |

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Run it

The code is the same everywhere. Only the address of the other party changes.

**Same machine**
```bash
python -m twoparty --role bob   --listen 127.0.0.1:5000        # terminal 1
python -m twoparty --role alice --peer   127.0.0.1:5000 --label local   # terminal 2
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

**Two devices** (same network, port 5000 open)
```bash
python -m twoparty --role bob   --listen 0.0.0.0:5000                   # laptop B
python -m twoparty --role alice --peer   <address of B>:5000 --label devices-wifi   # laptop A
```

**Single-device baseline** (no network)
```bash
python -m twoparty --task baseline --rounds 200
```

Results are printed as one JSON line. With `--out benchmark/results/results.csv`
they are also appended to a CSV file. Always set `--label` so runs can be told apart,
and note the network used (Wi-Fi, cable, hotspot).

## Layout

```
src/twoparty/
  curve.py           secp256k1 helpers (libsecp256k1 via coincurve)
  ecdsa_baseline.py  single-device ECDSA with the formulas from our slides
  sharing.py         additive secret sharing
  net.py             message channel (JSON, length-prefixed), counts messages and bytes
  mta.py             multiplicative-to-additive conversion (open)
  protocol.py        two-party signing (open)
  bench.py           timing helpers, echo and baseline benchmarks
tests/               pytest
benchmark/results/   measurement output
```

## Notes

- Educational code. Not side-channel safe, never use it with real funds.
- Use test keys only. Do not commit keys or `.env` files.
