# Threat model and attack surface

> Draft for the final documentation (due January 2027). Asked for by Nan Cheng
> in the meeting of 30 Oct 2026: state the threat model clearly and show what
> a malicious party could do. We describe the attacks; we do not fix them.

## 1. Our model: semi-honest

Our protocol is secure only in the **semi-honest** (honest-but-curious) model:

- Both parties run the unmodified program and send exactly the messages it computes.
- Each party may still look at everything it receives and try to learn from it.
- The network is out of scope. Messages travel over plain TCP, with no
  encryption and no authentication.

Under these assumptions, neither party learns the other's key share $d_i$,
nonce share $k_i$ or mask share $\gamma_i$. A stolen copy of **one** device's
data is useless on its own, because $d = d_1 + d_2$ never exists anywhere.

**What we left out compared with GG18** (Gennaro & Goldfeder, CCS 2018 [GG18]),
on which our signing is based:

| Left out | What it does in GG18 | Why we could leave it out |
|---|---|---|
| Commitments (commit, then reveal) to $Q_i$ in keygen and to $\Gamma_i$ in signing | The party that speaks second cannot adapt its value to the first one | A semi-honest party picks its value honestly, before it sees the other's |
| Zero-knowledge proofs of knowledge of $d_i$ and $\gamma_i$ (Schnorr) | Each party proves that it knows the discrete log of what it sent | Semi-honest parties know their own values by definition |
| Range proofs in MtA (Alice's $a$, Bob's $b$ and $\beta'$) | Inputs to MtA lie in the ranges the security proof needs | Our own code checks the ranges, and a semi-honest party runs our code |
| Proof that the Paillier modulus $N$ is well formed (a product of two large primes, no small factors) | Stops a party from choosing a weak key | Alice generates $N$ honestly with `paillier.keygen` |
| MtA with check (MtAwc, which proves $b \cdot G = Q_2$) and the signature check in phase 5 | Detects a party that used wrong inputs | Not needed if nobody deviates |

The supervisors fixed this model (semi-honest, no range proofs) at the start.
It keeps the protocol small enough to build, measure and explain in one semester.

## 2. Notation (our protocol)

All values are mod $n$ unless stated otherwise. Alice owns the only Paillier
key $(N, \lambda, \mu)$. Bob only knows $N$.

**MtA$(a, b)$** turns a product of two secrets into two additive shares:

1. Alice sends $c_A = \mathrm{Enc}(a)$.
2. Bob picks $\beta' \in [0, B)$ with $B = n^2 \cdot 2^{40}$. He sends
   $c_B = c_A^{\,b} \cdot \mathrm{Enc}(\beta') = \mathrm{Enc}(a b + \beta')$ and
   keeps $\beta = -\beta' \bmod n$.
3. Alice decrypts $v = a b + \beta'$ **as a whole number** and keeps $\alpha = v \bmod n$.

Then $\alpha + \beta \equiv ab$. Signing runs four MtAs:
$(k_1, \gamma_2)$, $(\gamma_1, k_2)$, $(k_1, d_2)$ and $(d_1, k_2)$.
Alice is always the $a$ side.

Bob checks only one thing about $N$, in `mta.check_key`: that
$N > n^2 + B$, so that $ab + \beta'$ never wraps around mod $N$.

## 3. Nan's example: MtA without a bound on $\beta'$ leaks key shares

Everything Alice learns in an MtA is $v = ab + \beta'$. The mask $\beta'$ is
the only thing that hides $ab$. If $\beta'$ is missing, too small, or not in
the range the protocol assumes, $v$ reveals information about $b$. In the MtA
$(k_1, d_2)$, $b$ is Bob's key share.

### 3a. Bob leaves out $\beta'$ (our experiment)

With $\beta' = 0$ (`--set mask=false`, `mta.recover_b`), Alice decrypts
$v = k_1 d_2$ in the MtA $(k_1, d_2)$. She knows $k_1$, so

$$d_2 = \alpha \cdot k_1^{-1} \bmod n, \qquad d = d_1 + d_2 .$$

From then on Alice can sign anything alone. The signature of that session is
still valid, so Bob notices nothing. Our tests check exactly this, also with
every speed-up switched on (`tests/test_protocol.py`, `tests/test_building_blocks.py`).

Bob hurts himself here, so a malicious party would not do this. The case
models a **buggy or misconfigured implementation**. It shows that
$\beta'$ is not optional.

### 3b. Malicious Alice: an input $a$ outside $[0, n)$

Bob cannot check what is inside $c_A$, because it is encrypted. Our code
checks $0 \le a < n$ only on **Alice's own** side, so a modified Alice skips
that check. Without a range proof she can send $\mathrm{Enc}(A)$ for any $A < N$.

Take $A = 2^{560}$, which is larger than $B \approx 2^{552}$ for secp256k1.
Then $A \cdot b < 2^{816} < N$, so Bob's answer decrypts without wrapping to

$$v = A \cdot b + \beta', \qquad 0 \le \beta' < B < A \quad\Longrightarrow\quad b = \lfloor v / A \rfloor .$$

If Alice does this in the MtA $(k_1, d_2)$, she learns $d_2$ **exactly, in one
signing session**. The signature of that session fails, because her
$\sigma_1$ is wrong. By then the key is lost.

- **Missing:** a range proof on Alice's input. GG18 has Alice prove $a < n^3$
  (the proof from MacKenzie–Reiter) before Bob answers.
- **Known attacks:** Tymokhanov and Shlomovits [AlphaRays] extract the full
  key from GG18/GG20 implementations by exploiting the MtA sub-protocol.
  Makriyannis and Peled [MP-note] describe attacks on GG18 that come from MtA
  ciphertexts with no range proof.

### 3c. Malicious Alice: a weak Paillier key

Bob checks only the size of $N$. Alice could choose $N$ with small prime
factors, or $N$ not a product of two primes. Decryption then works modulo
these small factors separately, and each answer from Bob can leak $b$ modulo
a small prime. Collected over many sessions with the Chinese remainder
theorem, these residues give Bob's key share.

- **Missing:** a proof that $N$ is well formed (square-free, no small
  factors) and has the advertised size.
- **Known attacks:** The second attack in [AlphaRays] needs only a Paillier
  key that is too small, a check most implementations lacked.
  Makriyannis, Yomtov and Galansky [MYG] extract keys with a modulus that has
  16 small factors ("6ix1een") and similar flaws in deployed wallets.

### 3d. Malicious Bob: $\beta'$ too large (selective failure)

Bob is supposed to draw $\beta' < B$. If instead he picks $\beta'$ close to $N$,
then $d_1 k_2 + \beta'$ wraps around mod $N$ in the MtA $(d_1, k_2)$ exactly when

$$d_1 \ge (N - \beta') / k_2 .$$

When it wraps, Alice's share is off by $N \bmod n$, and the signature at the
end is invalid. Bob sees $r$ and $s$ and can check validity himself. Each
session therefore tells him whether $d_1$ is above a threshold he chose,
since he knows $k_2$. With a binary search, about 256 sessions reveal $d_1$.
To Alice these look like occasional failed signatures.

- **Missing:** a range proof on Bob's $b$ and $\beta'$ (Bob's proof in GG18's MtA).
- **Known attacks:** leaks through whether a signature succeeds or fails
  (selective failure) are the type of leak used in [AlphaRays]. Their exact
  attack differs in its details.

### 3e. Why $B = n^2 \cdot 2^{40}$, and what goes wrong with a small $B$

Alice sees $v = ab + \beta'$ with $ab < n^2$ and $\beta'$ uniform in $[0, B)$.
For two different products $ab$ and $a b^\*$, the distributions of $v$ differ
by a statistical distance of at most $n^2 / B$. With $B = n^2 \cdot 2^{40}$,
that is $2^{-40}$ per MtA. Alice learns something about $b$ only if $v$ falls
into one of the two edges of width $n^2$, i.e. $v < n^2$ or $v \ge B$.

The study mode of our demo uses $2^{4}$ instead of $2^{40}$, so that the
numbers fit on screen. Then the edges are hit with probability up to
$2^{-4} = 1/16$ per MtA. On the toy curve ($n = 313$) the mask also hides
very little. The demo marks this mode as insecure. A flaky test
(`test_demo_signs`) shows the same effect: now and then the "attack"
guesses Bob's share by chance.

$N > n^2 + B$ is the second condition. Without it, $v$ would wrap around
mod $N$ and $\alpha$ would be wrong, even for honest parties.

## 4. Other attacks by a malicious party

| What is missing | Attack | Consequence | Known fix (not built) |
|---|---|---|---|
| Commitment and proof of knowledge for $Q_i$ in setup | Alice sends $Q_1$ first. Bob answers $Q_2 = x \cdot G - Q_1$ for an $x$ he chose (a rogue key) | $Q = x \cdot G$: **Bob alone controls the wallet**, and Alice still believes it is shared | Commit to $Q_i$ before revealing it, plus a Schnorr proof of knowledge of $d_i$ (GG18 key generation) |
| Commitment to $\Gamma_i$ | The party that speaks second chooses $\Gamma_2$ (and $\delta_2$) after seeing $\Gamma_1$ | It can steer $R$, break the link between $R$ and $k$, or make the signature invalid | Commit to $\Gamma_i$ in round 1, open it with a proof of knowledge of $\gamma_i$ after $\delta$ (GG18 phases 1 and 4) |
| Check of $\delta_i$ and $s_i$ | Either party sends a wrong $\delta_i$ or $s_i$ | Invalid signature (denial of service). Combined with 3d it becomes a leak | MtAwc, plus the phase-5 check in GG18 before the $s_i$ are released |
| Fairness | Alice sends $s_1$ first. Bob then knows the whole signature and can withhold $s_2$ | Bob can broadcast the transaction or refuse; Alice gets nothing | None in 2-of-2 without a third party. Accepted in practice |
| Aborts | Either party stops at any point | No signature. In 2-of-2, that is a veto | By design. Identifiable aborts [CGGMP] only help with more parties |
| Network security (out of our model) | An attacker on the Wi-Fi replaces $Q_2$, $N$ or $c_B$ in transit | Everything in section 3 and this table, without being a party | An authenticated, encrypted channel (TLS with pinned keys) |

## 5. What this means for the custody application

Our use case: Alice and Bob jointly own a wallet, and every transaction needs both.

- **Protected:** a thief who copies the data of **one** device, with $d_1$ or
  $d_2$, cannot sign. Each share alone is a uniformly random number. This
  is the story of our video.
- **Not protected:** a co-owner who **modifies their program**. With the
  attacks in 3b and 3c, Alice learns Bob's share in one session or a few.
  With 3d, Bob learns Alice's share in about 256 sessions. With the rogue
  key in section 4, Bob controls the wallet from the start. Our protocol
  therefore fits two devices of the **same owner** (laptop and phone), or
  owners who trust each other's software, but not mutually distrusting owners.
- **Not protected:** an attacker on the network, because we do not use TLS.
- For mutually distrusting owners, the missing pieces above are needed, as
  in GG18, CGGMP or Lindell's two-party protocol [Lindell17].

## References

- **[GG18]** R. Gennaro, S. Goldfeder. *Fast Multiparty Threshold ECDSA with
  Fast Trustless Setup.* ACM CCS 2018. ePrint 2019/114. ✅ verified
- **[Lindell17]** Y. Lindell. *Fast Secure Two-Party ECDSA Signing.*
  CRYPTO 2017, LNCS 10402, pp. 613–644. ePrint 2017/552. A journal version
  appeared in J. Cryptology 34:44 (2021). ✅ verified
- **[CGGMP]** R. Canetti, R. Gennaro, S. Goldfeder, N. Makriyannis, U. Peled.
  *UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts.*
  ACM CCS 2020. ePrint 2021/060. ✅ verified
- **[AlphaRays]** D. Tymokhanov, O. Shlomovits. *Alpha-Rays: Key Extraction
  Attacks on Threshold ECDSA Implementations.* ePrint 2021/1621, December 2021.
  ✅ verified (two attacks on MtA in GG18/GG20; full key from 8 signatures in
  their proof of concept; the second needs only a small Paillier key)
- **[MP-note]** N. Makriyannis, U. Peled. *A Note on the Security of GG18.*
  Technical note published by Fireblocks (info.fireblocks.com). ⚠️ Title and
  authors verified. **Not on ePrint, year not confirmed** (secondary sources
  say 2021). Check before submitting.
- **[MYG]** N. Makriyannis, O. Yomtov, A. Galansky. *Practical Key-Extraction
  Attacks in Leading MPC Wallets.* ePrint 2023/1234. ✅ verified. ⚠️ ACM CCS
  2024 (DOI 10.1145/3658644.3670359) appears in the ACM Digital Library;
  confirm the venue before citing it.
