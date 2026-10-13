"""Two-party signing on top of MtA. Not implemented yet.

Planned flow (details follow the supervisors' description):
  1. Both parties hold additive shares d1, d2 of the key (see sharing.py).
  2. They create the nonce k together, so neither knows it alone.
  3. MtA handles the products of two secrets (k^-1 and d).
  4. Together they output one normal (r, s) that ecdsa_baseline.verify accepts.
"""


def sign_alice(channel, d1: int, msg: bytes):
    raise NotImplementedError("two-party signing is not implemented yet")


def sign_bob(channel, d2: int, msg: bytes):
    raise NotImplementedError("two-party signing is not implemented yet")
