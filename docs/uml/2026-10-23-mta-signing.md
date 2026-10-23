# UML: Bruno's state vs. session 23 Oct 2026 (MtA, signing, demo)

Made from the code with `python scripts/uml.py`, not drawn by hand. Each box is a module in `src/twoparty` with its public functions and classes; an arrow `A ..> B` means "A uses B". In the after picture **green = new module**, **yellow = changed module**, and single functions are marked (new) or (changed).

Tests: 46 before → 88 after (test functions, not counting parameter variants).

## What changed

| Module | before | after | what changed |
|---|---|---|---|
| `__main__.py` | 5 | 5 | changed: `main`, `run_bob`, `run_alice`, `report` |
| `bench.py` | 5 | 7 | new: `sign_alice`, `sign_bob` |
| `curve.py` | 7 | 7 | unchanged |
| `demo.py` | – | 17 | **new module** |
| `ec.py` | 1 | 1 | unchanged |
| `ecdsa_baseline.py` | 4 | 4 | unchanged |
| `ecdsa_pure.py` | 9 | 9 | unchanged |
| `mta.py` | 2 | 9 | new: `mask_bound`, `key_bits`, `check_key`, `alice_encrypt`, `bob_respond`, `alice_decrypt`, `recover_b`; changed: `mta_alice`, `mta_bob` |
| `net.py` | 4 | 4 | changed: `connect` |
| `paillier.py` | – | 9 | **new module** |
| `protocol.py` | 2 | 4 | new: `setup_alice`, `setup_bob`; changed: `sign_alice`, `sign_bob` |
| `sharing.py` | 2 | 2 | unchanged |
| `trace.py` | 9 | 9 | unchanged |

## Before (`ce76a3b`)

```mermaid
classDiagram
direction LR
class main["__main__.py"] {
  +addr(text)
  +main(argv)
  +run_bob(a)
  +run_alice(a)
  +report(a, samples, stats)
}
class bench["bench.py"] {
  +summarize(samples_ms)
  +baseline(rounds)
  +echo_alice(channel, rounds, payload)
  +echo_bob(channel)
  +append_csv(path, row)
}
class curve["curve.py"] {
  +rand_scalar()
  +inv(x)
  +base_mult(k)
  +point_mult(point, k)
  +point_add()
  +x_coord(point)
  +der_encode(r, s)
}
class ec["ec.py"] {
  +class Curve
}
class ecdsa_baseline["ecdsa_baseline.py"] {
  +message_hash(msg)
  +keygen()
  +sign(d, msg)
  +verify(q, msg, sig)
}
class ecdsa_pure["ecdsa_pure.py"] {
  +message_hash(curve, msg)
  +rand_scalar(curve, rng)
  +keygen(curve, d, rng)
  +class SignSteps
  +sign_steps(curve, d, e, k)
  +sign(curve, d, msg, k, …)
  +class VerifySteps
  +verify_steps(curve, Q, e, sig)
  +verify(curve, Q, msg, sig)
}
class mta["mta.py"] {
  +mta_alice(channel, a)
  +mta_bob(channel, b)
}
class net["net.py"] {
  +class Channel
  +listen(host, port)
  +accept(srv)
  +connect(host, port, retries, delay)
}
class protocol["protocol.py"] {
  +sign_alice(channel, d1, msg)
  +sign_bob(channel, d2, msg)
}
class sharing["sharing.py"] {
  +share(secret, n, d1)
  +combine()
}
class trace["trace.py"] {
  +class StepError
  +class Step
  +encode(v)
  +run_steps(curve, values)
  +curve_info(c)
  +build_trace(curve, values)
  +default_values(curve, seed, message)
  +build_vectors(seed)
  +main(argv)
}
main ..> bench
main ..> net
main ..> protocol
bench ..> ecdsa_baseline
ecdsa_baseline ..> curve
ecdsa_pure ..> ec
sharing ..> curve
trace ..> ec
trace ..> ecdsa_pure
trace ..> sharing
```

## After (working tree)

```mermaid
classDiagram
direction LR
class main["__main__.py"] {
  +addr(text)
  +main(argv) (changed)
  +run_bob(a) (changed)
  +run_alice(a) (changed)
  +report(a, samples, stats, extra) (changed)
}
class bench["bench.py"] {
  +summarize(samples_ms)
  +baseline(rounds)
  +echo_alice(channel, rounds, payload)
  +echo_bob(channel)
  +sign_alice(channel, curve, rounds) (new)
  +sign_bob(channel, curve) (new)
  +append_csv(path, row)
}
class curve["curve.py"] {
  +rand_scalar()
  +inv(x)
  +base_mult(k)
  +point_mult(point, k)
  +point_add()
  +x_coord(point)
  +der_encode(r, s)
}
class demo["demo.py"] {
  +addr(text) (new)
  +greet(ch) (new)
  +expect_greeting(ch, where) (new)
  +fmt(v, full) (new)
  +print_values(values, full) (new)
  +explain(step, values, v, curve, …) (new)
  +class Narrator (new)
  +check(who, curve, Q, msg, …) (new)
  +join(a, who) (new)
  +run_alice(a) (new)
  +attack(v, d1, Q2, curve, …) (new)
  +run_bob(a) (new)
  +class Wire (new)
  +class EventLog (new)
  +choose(question, options, given) (new)
  +run_observer(a) (new)
  +main(argv) (new)
}
class ec["ec.py"] {
  +class Curve
}
class ecdsa_baseline["ecdsa_baseline.py"] {
  +message_hash(msg)
  +keygen()
  +sign(d, msg)
  +verify(q, msg, sig)
}
class ecdsa_pure["ecdsa_pure.py"] {
  +message_hash(curve, msg)
  +rand_scalar(curve, rng)
  +keygen(curve, d, rng)
  +class SignSteps
  +sign_steps(curve, d, e, k)
  +sign(curve, d, msg, k, …)
  +class VerifySteps
  +verify_steps(curve, Q, e, sig)
  +verify(curve, Q, msg, sig)
}
class mta["mta.py"] {
  +mask_bound(n, mask_bits) (new)
  +key_bits(n, mask_bits) (new)
  +check_key(N, n, mask_bits) (new)
  +alice_encrypt(N, a, n) (new)
  +bob_respond(N, c_A, b, n, …) (new)
  +alice_decrypt(key, c_B, n) (new)
  +mta_alice(channel, key, a, n, …) (changed)
  +mta_bob(channel, N, b, n, …) (changed)
  +recover_b(alpha, a, n) (new)
}
class net["net.py"] {
  +class Channel
  +listen(host, port)
  +accept(srv)
  +connect(host, port, retries, delay) (changed)
}
class paillier["paillier.py"] {
  +is_probable_prime(x, rounds) (new)
  +random_prime(bits) (new)
  +class Key (new)
  +key_from_primes(p, q) (new)
  +keygen(bits) (new)
  +encrypt(N, m, r) (new)
  +decrypt(key, c) (new)
  +add(N, c1, c2) (new)
  +mul_const(N, c, k) (new)
}
class protocol["protocol.py"] {
  +setup_alice(channel, curve, key, show, …) (new)
  +setup_bob(channel, curve, show, mask_bits) (new)
  +sign_alice(channel, curve, key, d1, …) (changed)
  +sign_bob(channel, curve, N, d2, …) (changed)
}
class sharing["sharing.py"] {
  +share(secret, n, d1)
  +combine()
}
class trace["trace.py"] {
  +class StepError
  +class Step
  +encode(v)
  +run_steps(curve, values)
  +curve_info(c)
  +build_trace(curve, values)
  +default_values(curve, seed, message)
  +build_vectors(seed)
  +main(argv)
}
main ..> bench
main ..> ec
main ..> net
bench ..> ecdsa_baseline
bench ..> ecdsa_pure
bench ..> protocol
demo ..> ec
demo ..> ecdsa_baseline
demo ..> ecdsa_pure
demo ..> mta
demo ..> net
demo ..> protocol
demo ..> trace
ecdsa_baseline ..> curve
ecdsa_pure ..> ec
mta ..> paillier
protocol ..> ec
protocol ..> ecdsa_pure
protocol ..> mta
protocol ..> paillier
sharing ..> curve
trace ..> ec
trace ..> ecdsa_pure
trace ..> sharing
style main fill:#fff1c2,stroke:#b8860b
style bench fill:#fff1c2,stroke:#b8860b
style demo fill:#d8f5d0,stroke:#2e7d32
style mta fill:#fff1c2,stroke:#b8860b
style net fill:#fff1c2,stroke:#b8860b
style paillier fill:#d8f5d0,stroke:#2e7d32
style protocol fill:#fff1c2,stroke:#b8860b
```
