"""Multiplicative-to-additive conversion (MtA). Not implemented yet.

Goal: Alice holds a, Bob holds b. Afterwards Alice holds alpha and Bob holds
beta with alpha + beta = a*b (mod N), and neither learns the other's input.

We implement the variant described by our supervisors (e.g. based on
Paillier encryption or on oblivious transfer). Fill these in once the
simplified description is available.
"""


def mta_alice(channel, a: int) -> int:
    """Alice's side. Returns alpha."""
    raise NotImplementedError("waiting for the MtA description from the supervisors")


def mta_bob(channel, b: int) -> int:
    """Bob's side. Returns beta."""
    raise NotImplementedError("waiting for the MtA description from the supervisors")
