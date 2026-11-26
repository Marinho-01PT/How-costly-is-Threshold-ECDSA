# How we did it, in plain words

*For the SCS Student Conference and everyone who is new to the project.
The technical details are in `docs/report/` and `docs/sessions/`.*

## The problem

A crypto wallet is protected by one secret number, the private key. Whoever
has it can spend the money. If it sits on one device and that device is
hacked, the money is gone.

The idea: **split the key between two devices.** Alice holds one half, Bob
holds the other. To send money, both must take part. A thief who hacks one
device holds only a useless half.

For Bitcoin and Ethereum this is harder than it sounds. They use a signature
scheme called **ECDSA**, and its formula **multiplies two secret numbers**.
Halves that are added together do not survive a multiplication. You cannot
just compute with your half and add the results.

The fix is a small sub-protocol called **MtA** (multiplicative-to-additive).
It turns "a times b" into "something for Alice plus something for Bob",
without either of them learning the other's number. It uses **Paillier
encryption**, a kind of encryption you can still calculate with while the
numbers stay locked.

Our question: **how much does splitting the key cost?** How much slower is
it, how many messages and bytes does it need, and what happens if you
leave out a safety step?

## What we built, step by step

1. **Normal ECDSA first.** One device, one key, as the reference. We wrote it
   ourselves in Python and checked every signature against libsecp256k1, the
   library Bitcoin itself uses.
2. **A small "toy" curve.** Same formula as Bitcoin's curve, but with only 313
   points, so every number fits on a sheet of paper. This made it possible
   to follow and check every step by hand.
3. **Paillier encryption and MtA**, written ourselves, about 50 and 100
   lines, so we understand every line instead of trusting a black box.
4. **The two-party protocol**, based on Gennaro & Goldfeder (2018), simplified
   for two parties. Alice and Bob run as two programs that talk over the
   network. One signature needs **14 messages**. The result is a completely
   normal ECDSA signature: anyone can check it, nobody can tell that two
   devices made it.
5. **The experiment.** If Bob leaves out one random number (β′) inside the
   MtA, Alice can read his key half straight out of her result. Then she
   holds the whole key and can spend the money alone. Our code shows this live.
6. **A demo you can watch**: Alice, Bob and an observer in three windows, one
   step per key press. Every message and number is visible.
7. **A visualizer in the browser** that walks through the protocol on the toy
   curve.
8. **Building blocks you can swap.** Every part of the protocol has
   alternatives, for example a faster number library or a smarter way to
   decrypt. You can switch each one on or off and measure what it changes
   (details below).
9. **Two laptops on the same Wi-Fi** find each other with a 4-digit pairing
   code and run the demo or the benchmark against each other.
10. **An interface** with one row per building block: a study mode that goes
    through one signature step by step, and a benchmark mode that measures
    many signatures and draws the results.

## How we measured

- **What we time:** only the signing itself. Generating keys and preparing
  numbers in advance are timed separately, because a real wallet does
  those once.
- **What we count:** time per signature, signatures per second, time to
  check a signature, messages and bytes per signature.
- **Every signature is checked** with libsecp256k1, outside the timing. A
  wrong signature stops the run, so no fast but wrong variant can win.
- **Repeated runs:** 20 signatures per variant. We report average, median
  and the slowest 5 %.
- **Where:** first on one laptop (two programs talking over localhost),
  then over Wi-Fi between two laptops.

## What we found

| What we changed | Time per signature | |
|---|---|---|
| Our first version | 2.3 s | |
| Faster number library (gmpy2, which uses GMP) | 0.12 s | 18× faster |
| Preparing encryption randomness in advance | 0.82 s | 2.8× faster |
| Smarter decryption (Chinese remainder theorem) | 1.7 s | 1.3× faster |
| Bitcoin's own curve library | 2.2 s | almost no change |
| Compact binary messages instead of text | 2.2 s | same time, 57 % fewer bytes |
| Sending Alice's encrypted key half only once (MtA reuse) | 1.6 s | 1.45× faster, 12 instead of 14 messages |
| Bundling messages (4 instead of 14) | 2.3 s | same time on one laptop, matters over Wi-Fi |
| Bigger, safer Paillier key (3072 instead of 2048 bit) | 6.9 s | 3× slower |
| **Everything together** | **0.016 s** | **143× faster, 4 messages, 3.4 kB** |

*Measured 26 Nov 2026 on one MacBook, 20 signatures each. Wi-Fi numbers
between two laptops are added once measured.*

**The three most important lessons:**

1. **The encryption is the expensive part, not the curve.** Almost all of the
   time goes into Paillier, which computes with numbers of 4096 bits. The
   elliptic curve itself hardly matters. Swapping in Bitcoin's highly
   optimised curve library changed signing time by only 1 %.
2. **How you compute matters more than what you compute.** The same maths
   with a better number library is 18 times faster. With all tricks
   together, splitting the key costs 16 ms per signature and 4 messages, fast enough for
   a real wallet.
3. **Security has a price, and leaving it out is dangerous.** Our protocol
   assumes both parties follow the rules ("semi-honest"). Real wallets add
   proofs (range proofs, zero-knowledge proofs) against a cheating partner.
   Our experiment shows what happens without that protection: one missing
   random number, and the partner steals the whole key.

## What we left out on purpose

- **No protection against a cheating partner.** Our supervisors agreed that a
  semi-honest prototype is enough. The documentation describes which attacks
  would then be possible and how real wallets prevent them
  (`docs/report/threat-model.md`).
- **No real Bitcoin network.** The demo signs a transaction text such as
  "Alice and Bob send 0.1 BTC to Carol". The signature would be valid on
  Bitcoin, but nothing is sent.

## Team

Keanu Belo da Silva and Bruno Marinho, HSG Bachelor project 2026, supervised
by Prof. Katerina Mitrokotsa and Nan Cheng.
