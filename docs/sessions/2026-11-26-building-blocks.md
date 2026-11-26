# Session 26 Nov 2026: building blocks you can swap, and the first numbers

- **Branch:** `building-blocks`, started from `main` at `b8af8d1` (merge of PR #1)
- **Basis:** the table "Building blocks and their implementations" on our
  protocol sheet (Besprechung 30.10.), and Nan's wish for throughput,
  signing and verification efficiency instead of a comparison with plain ECDSA.

## What this session was about

Until now every row of the table had exactly one variant in the code, and
`benchmark/results/` was empty. Goal: make the variants swappable, check that
every one still gives a valid ECDSA signature, and measure them.

## What we did

1. **`config.py`**: one `Config` field per row of the table. `Config()` is the
   original protocol. `ROWS` lists the rows with their variants and the ones
   still planned, for the matrix now and the interface later.
2. **`paillier.Ops`**: one party's Paillier operations with the chosen variants.
   The naive functions above it stay untouched, so the demo, the trace and the
   visualizer show exactly what they showed before.
   - `bignum=gmpy2`: same numbers, `pow` from GMP.
   - `paillier_dec=crt`: decrypt mod p² and q² with exponents p−1 and q−1, combine.
   - `paillier_enc=crt`: r^N mod p² and mod q², combine. Only Alice knows p and q;
     Bob falls back to naive (`Ops.enc_used` says what really ran).
   - `paillier_enc=precomputed`: r^N does not depend on the message, so a pool is
     filled before signing (offline, timed apart). Online one multiplication is left.
3. **`ec_libsecp.py`**: secp256k1 from libsecp256k1 behind the interface of
   `ec.Curve`, so the protocol code is the same for both curve variants.
4. **`net.py`**: binary message format next to JSON. The hello message stays
   JSON, both sides switch right after it.
5. **`mta.py`, `protocol.py`**: take an optional `ops`. Without it, nothing changes.
6. **`bench.py`, `__main__.py`**: `--task sign --set row=variant` and
   `--task matrix`, which runs the original, each variant alone, and all
   speed-ups together. Every signature is checked with libsecp256k1 outside
   the timing.
7. **`tests/test_building_blocks.py`**: every variant signs validly, Paillier
   variants give the same plaintexts as the naive code, binary round trip,
   the experiment without β′ still leaks d2 with all speed-ups on.

## Results

See [matrix-2026-11-26-localhost.csv](../../benchmark/results/matrix-2026-11-26-localhost.csv).

| Variant | Signing, mean (median) | Speed-up | Signatures/s | Verification | Bytes/signature | Offline |
|---|---|---|---|---|---|---|
| original | 2262.2 ms (2252.8) | 1.00× | 0.44 | 17.93 ms | 10'657 | 0 ms |
| libsecp256k1 in the protocol | 2241.5 ms (2229.4) | 1.01× | 0.45 | 0.07 ms | 10'656 | 0 ms |
| gmpy2 | 123.6 ms (123.5) | 18.31× | 8.09 | 16.60 ms | 10'656 | 0 ms |
| CRT decryption | 1727.2 ms (1725.0) | 1.31× | 0.58 | 16.56 ms | 10'656 | 0 ms |
| CRT encryption (Alice) | 2026.2 ms (1914.6) | 1.12× | 0.49 | 16.55 ms | 10'655 | 0 ms |
| precomputed r^N | 822.3 ms (822.0) | 2.75× | 1.22 | 16.47 ms | 10'656 | 14595 ms |
| 3072-bit Paillier key | 6862.1 ms (6847.0) | 0.33× | 0.15 | 16.50 ms | 15'588 | 0 ms |
| binary messages | 2244.7 ms (2244.6) | 1.01× | 0.45 | 16.57 ms | 4'540 | 0 ms |
| all speed-ups together | 16.1 ms (16.1) | 140.49× | 62.10 | 0.05 ms | 4'540 | 667 ms |

20 signatures per row, secp256k1, Alice and Bob as two processes on one MacBook (localhost), 14 messages per signature in every row. Offline = filling the r^N pool for 80 encryptions on each side, before signing.

## Open

- MtA reuse (Enc(d1) once, Enc(k1) reused), batched messages, two devices over Wi-Fi.
- Docker with delay still not run.
- Interface with one row per building block, study mode and benchmark mode.
- `tests/test_demo.py::test_demo_signs` fails now and then (also before this
  branch): in study mode the toy curve has only 313 points and β′ is 4 bits,
  so the attack sometimes guesses Bob's share by chance.
- For the report: threat model (semi-honest) and attack surface (β′ bound), as Nan asked.
