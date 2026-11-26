# Building blocks: variants, why they help, what we measured

> Draft for the final documentation. Code: `src/twoparty/config.py` (one field
> per building block), `paillier.Ops`, `ec_libsecp.py`, `net.py`.
> Raw numbers: `benchmark/results/matrix-2026-11-26-localhost.csv` and the
> session log `docs/sessions/2026-11-26-building-blocks.md`.

## 1. Methodology

- **Machine:** MacBook Air, Apple M3, 16 GB RAM, macOS. Python 3.13.2,
  coincurve (libsecp256k1), gmpy2 2.3.2.
- **Setup:** Alice and Bob run as two separate processes on the same machine
  and talk over a TCP socket on localhost. `python -m twoparty --task matrix
  --rounds 20` starts its own Bob.
- **Per row:** 20 signatures of the messages `tx-0` … `tx-19` on secp256k1
  with a 2048-bit Paillier key, unless the row says otherwise. One key per size
  is generated once and reused, so the prime search does not distort the
  comparison.
- **What is timed:** signing is timed on Alice's side, from her first message
  to the finished signature $(r, s)$. Because the protocol is strictly
  sequential, this includes Bob's computation and all 14 messages.
- **Timed apart:** Paillier key generation, setup (key shares, 2 messages)
  and the offline phase of precomputed encryption (filling the $r^N$ pools on
  both sides before signing).
- **Verification:** each finished signature is verified once with the
  chosen curve variant. That time is reported as "verification". Each
  signature is also checked once more, outside the timing; a wrong one would
  stop the run.
- **Reported:** mean, median and 95th percentile of the signing time,
  signatures per second ($20 / \sum t_i$, sequential), verification time,
  messages and bytes per signature.
- **Caveats:** localhost only (the Wi-Fi numbers are open, see section 5).
  The machine was not otherwise idle. 20 runs is enough for the large
  differences here, but too few to resolve differences below a few percent.

## 2. The building blocks and their variants

| Building block (`--set`) | Variants (first = original) |
|---|---|
| Curve arithmetic in the protocol (`curve`) | `pure`: our pure-Python curve (`ec.py`). `libsecp256k1`: the same calls through coincurve (`ec_libsecp.py`) |
| Big-number arithmetic (`bignum`) | `int`: Python integers. `gmpy2`: `pow` from GMP |
| Paillier decryption (`paillier_dec`) | `naive`, `crt` |
| Paillier encryption (`paillier_enc`) | `naive`, `crt` (Alice only), `precomputed` |
| Paillier key size (`paillier_bits`) | 2048, 3072 |
| Message format (`wire`) | `json`: numbers as decimal text. `binary`: numbers as raw bytes, with a small tag-length-value encoding |
| Safety experiment (`mask`) | with $\beta'$, without $\beta'$ (see `threat-model.md`) |
| Use of MtA | 4 separate MtAs. **Planned:** $\mathrm{Enc}(d_1)$ once at setup, $\mathrm{Enc}(k_1)$ reused. **[PLACEHOLDER: added by the MtA-reuse work]** |
| Message flow | 14 messages. **Planned:** batched into 4. **[PLACEHOLDER: added by the batching work]** |
| Network | localhost, Docker with added delay, two devices over Wi-Fi. **[PLACEHOLDER: Wi-Fi numbers]** |

### Paillier, naive

$$\mathrm{Enc}(m) = (1 + mN)\, r^N \bmod N^2, \qquad \mathrm{Dec}(c) = L\!\left(c^{\lambda} \bmod N^2\right) \mu \bmod N, \quad L(x) = \tfrac{x-1}{N}.$$

Both are one exponentiation modulo $N^2$ (4096 bits) with a 2048-bit
exponent. Everything else (the $(1 + mN)$ factor, the homomorphic addition
$c_1 c_2$) is a single multiplication and costs almost nothing.

### Decryption with the Chinese remainder theorem (CRT)

Alice knows $p$ and $q$. She decrypts modulo $p^2$ and $q^2$ separately,
with exponents $p - 1$ and $q - 1$:

$$m_p = L_p\!\left(c^{\,p-1} \bmod p^2\right) h_p \bmod p, \quad h_p = L_p\!\left((N+1)^{p-1} \bmod p^2\right)^{-1} \bmod p, \quad L_p(x) = \tfrac{x-1}{p},$$

and the same for $q$. She then combines with $m = m_p + p\,\big((m_q - m_p)\, p^{-1} \bmod q\big)$.
The values $h_p$, $h_q$ and $p^{-1} \bmod q$ are computed once per key.

**Expected speed-up:** each exponentiation has half the modulus size (2048
instead of 4096 bits) and half the exponent length (1024 instead of 2048
bits). With multiplication cost roughly quadratic in the size, one
exponentiation costs about $\tfrac12 \cdot \tfrac14 = \tfrac18$, and two cost
$\tfrac14$: about **4×** in theory.

### Encryption with CRT (Alice only)

$r^N \bmod N^2$ is computed as $r^{\,N \bmod p(p-1)} \bmod p^2$ and
$r^{\,N \bmod q(q-1)} \bmod q^2$, then combined. Here the exponent is **not**
shorter, because $p(p-1) \approx N$. Only the modulus halves. Expected speed-up:
$2 \cdot \tfrac14 = \tfrac12$, about **2×**. Bob does not know $p$ and $q$ and
falls back to naive encryption (`Ops.enc_used`).

### Precomputed $r^N$ (offline/online)

$r^N \bmod N^2$ does not depend on the message. Both parties fill a pool of
these values before signing (the offline phase). Online, encryption is one
multiplication, $(1 + mN)\cdot r^N \bmod N^2$. This moves the cost, it does
not remove it: the offline phase costs as much as the encryptions it replaces.
It pays off when there is idle time before a signature is needed.

### gmpy2

The same numbers and the same formulas. Only `pow(b, e, m)` runs in GMP
(C and assembly, with faster multiplication and Montgomery reduction)
instead of Python's own big-integer code.

### libsecp256k1 in the protocol

`ec_libsecp.LIBSECP` has the same interface as `ec.Curve` (`base_mul`,
`mul`, `add`), so `protocol.py` is unchanged. The conversion of $(x, y)$
tuples to coincurve objects and back is included in the measured time.

### Binary messages

Ciphertexts are numbers below $N^2$, about 4096 bits. As decimal text in JSON
they take about 1240 bytes; as raw bytes, about 520.

## 3. Cost of each operation (micro-benchmark)

Mean of 30 runs on the same machine, 2048-bit Paillier key, ms per operation:

| Operation | Python `int` | gmpy2 |
|---|---|---|
| Encryption, naive | 187.5 | 8.27 |
| Encryption, CRT (Alice) | 94.5 (1.98×) | 4.96 (1.67×) |
| Encryption, precomputed: online | 0.05 | 0.05 |
| Precomputing one $r^N$ (offline) | 179.5 | 8.25 |
| Decryption, naive | 180.4 | 8.21 |
| Decryption, CRT | 47.7 (3.78×) | 2.51 (3.28×) |
| $c_A^{\,b}$ (Bob, 256-bit exponent) | 23.3 | 1.09 |
| Homomorphic addition | 0.07 | 0.07 |

| Curve and network | Time |
|---|---|
| $k \cdot G$, pure Python / libsecp256k1 | 9.07 ms / 0.020 ms |
| $k \cdot P$, pure Python / libsecp256k1 | 8.90 ms / 0.032 ms |
| One ciphertext through JSON / binary (encode and decode) | 0.048 ms / 0.005 ms |
| Round trip of a small message over localhost | 0.059 ms |

The CRT factors match the theory: 3.8× for decryption (theory about 4×) and
2.0× for encryption (theory about 2×). Bob's $c_A^{\,b}$ is cheap because $b$
has only 256 bits instead of 2048.

## 4. Results of the matrix and how to read them

| Variant | Signing, mean | Speed-up | Signatures/s | Verification | Bytes/signature | Offline |
|---|---|---|---|---|---|---|
| original | 2262 ms | 1.00× | 0.44 | 17.9 ms | 10'657 | – |
| libsecp256k1 in the protocol | 2242 ms | 1.01× | 0.45 | 0.07 ms | 10'656 | – |
| gmpy2 | 124 ms | 18.3× | 8.09 | 16.6 ms | 10'656 | – |
| CRT decryption | 1727 ms | 1.31× | 0.58 | 16.6 ms | 10'656 | – |
| CRT encryption (Alice) | 2026 ms | 1.12× | 0.49 | 16.6 ms | 10'655 | – |
| precomputed $r^N$ | 822 ms | 2.75× | 1.22 | 16.5 ms | 10'656 | 14.6 s |
| 3072-bit Paillier key | 6862 ms | 0.33× | 0.15 | 16.5 ms | 15'588 | – |
| binary messages | 2245 ms | 1.01× | 0.45 | 16.6 ms | 4'540 | – |
| all speed-ups together | 16.1 ms | 140× | 62.1 | 0.05 ms | 4'540 | 0.67 s |
| MtA reuse | **[PLACEHOLDER]** | | | | | |
| batched messages (4) | **[PLACEHOLDER]** | | | | | |
| two devices over Wi-Fi | **[PLACEHOLDER]** | | | | | |

**The operation counts explain the matrix.** One signature has 4 MtAs. Alice
does 4 encryptions and 4 decryptions, and Bob 4 encryptions and 4
exponentiations $c_A^{\,b}$. Each party also does 2 curve multiplications,
$\Gamma_i$ and $R$. With the numbers from section 3:

- **Original:** $4(187.5 + 180.4) + 4(187.5 + 23.3) + 4 \cdot 9 \approx 2350$ ms. Measured: 2262 ms.
- **CRT decryption** saves $4 \cdot (180.4 - 47.7) = 531$ ms. Predicted 1730 ms, measured 1727 ms.
- **Precomputed $r^N$** removes 8 encryptions of about 180 ms each. Predicted
  about 820 ms, measured 822 ms. The offline phase (14.6 s for 80 values per
  side) is the same work, done earlier.

What this means:

1. **Paillier dominates.** In the original protocol, curve arithmetic is
   about 36 ms of 2262 ms (1.6 %). Messages take less than 1 ms. That is why
   libsecp256k1 does not speed up signing (1.01×). It only speeds up
   verification, from 17.9 ms to 0.07 ms: plain ECDSA verification is pure
   curve arithmetic.
2. **gmpy2 is the largest single factor (18×).** Every Paillier
   exponentiation gets about 22× faster. The curve, still in pure Python,
   then becomes a visible part of the remaining 124 ms.
3. **Binary messages save bytes, not time, on localhost:** 4540 instead of
   10657 bytes per signature (−57 %), with the same time. On a slow link this
   changes, see the Wi-Fi placeholder.
4. **3072-bit keys** make Paillier about 3× slower (6862 ms), as expected for
   exponentiation (cost grows roughly with the cube of the size:
   $1.5^3 \approx 3.4$). Messages grow by 46 %.
5. **The speed-ups multiply.** Together they reach 16 ms per signature,
   62 signatures per second: 140× the original.

## 5. Open rows

- **MtA reuse** ($\mathrm{Enc}(d_1)$ once at setup, $\mathrm{Enc}(k_1)$ for two
  MtAs): **[PLACEHOLDER: description, effect on encryptions per signature,
  measured numbers]**
- **Batched messages (14 → 4):** **[PLACEHOLDER]**
- **Two devices over Wi-Fi:** **[PLACEHOLDER: setup, round-trip time, signing
  time with JSON and binary]**

## 6. Would rewriting libsecp256k1 make it faster?

No, for two reasons.

1. **libsecp256k1 is already one of the fastest secp256k1 libraries there is.**
   Bitcoin Core uses it. It is written in C with hand-tuned field arithmetic
   (and assembly for some platforms) and has been optimized and reviewed for
   more than ten years. A rewrite by us would almost certainly be slower and
   less safe (constant time, edge cases).
2. **The curve is not where the time goes.** With libsecp256k1, all curve
   operations of one signature take about 0.1 ms. That is less than 1 % of the
   16 ms in the fastest configuration, and 0.005 % of the original.

**Where the remaining 16 ms go** (fastest configuration, from section 3):

| Part | Per signature | Share |
|---|---|---|
| Alice: 4 CRT decryptions | $4 \times 2.51 \approx 10.0$ ms | ~62 % |
| Bob: 4 exponentiations $c_A^{\,b}$ | $4 \times 1.09 \approx 4.4$ ms | ~27 % |
| 8 precomputed encryptions (online) | $8 \times 0.05 \approx 0.4$ ms | ~3 % |
| 14 messages over localhost | about 0.4–0.8 ms | ~3–5 % |
| Curve (libsecp256k1), hashing, Python overhead | about 0.3 ms | ~2 % |
| **Sum** | ≈ 15.5 ms (measured: 16.1 ms) | |

A cProfile run of 20 signatures with Alice and Bob in separate processes
confirms the picture. Apart from the one-time key generation, almost all of
Alice's time is in `gmpy2.powmod`, the CRT decryptions. Bob spends most of his
time in `recv`, waiting for Alice, and the rest in `gmpy2.powmod`, his
$c_A^{\,b}$.

**What would really help:**

- **Fewer Paillier operations.** MtA reuse saves encryptions, but decryptions
  stay at 4 per signature. Protocols that avoid Paillier altogether, using
  oblivious transfer as in Doerner et al. (IEEE S&P 2018/2019), trade
  computation for more communication.
- **Doing decryptions in parallel.** The 4 MtAs are independent. Alice could
  decrypt all 4 at once on 4 cores, or run them in one batch (see the batching
  row).
- **A compiled implementation of Paillier,** in C or Rust with GMP and fixed
  window exponentiation. It would gain somewhat over gmpy2, but far less than
  gmpy2 gained over Python `int`, because gmpy2 already runs the expensive part
  in GMP.
- **Not relevant:** a faster curve library, or a faster message format on
  localhost.
