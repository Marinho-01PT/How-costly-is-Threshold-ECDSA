"""Multiplicative-to-additive conversion (MtA), with Paillier.

Alice holds a, Bob holds b (both mod n). Afterwards Alice holds alpha and Bob
holds beta with alpha + beta = a*b (mod n). Neither learns the other's input.
Only Alice has a Paillier key; Bob only gets N.

    Alice -> c_A = Enc(a)
    Bob      beta' random in [0, B)
    Bob   -> c_B = c_A^b * Enc(beta') = Enc(a*b + beta')     keeps beta = -beta' mod n
    Alice    alpha = Dec(c_B) mod n

Alice decrypts a*b + beta' as a whole number, not mod n. Since a*b < n^2 and
B = n^2 * 2^40, beta' hides a*b (statistical distance below 2^-40). N > n^2 + B
makes sure the sum never wraps around mod N, so the final mod n is correct.

Semi-honest model, as our supervisors specified: both parties follow the
protocol, so there are no range proofs. mask=False leaves out beta' for the
experiment: Alice then decrypts a*b itself (see recover_b).

mask_bits is the 40 in B = n^2 * 2^40. Only the demo's study mode lowers it
(to 4), so that every number stays small enough to calculate along. Then
beta' hides a*b badly: insecure, for learning only.
"""
import secrets

from . import paillier
from .paillier import Key

MASK_BITS = 40  # as advised by our supervisors


def mask_bound(n: int, mask_bits: int = MASK_BITS) -> int:
    """B = n^2 * 2^mask_bits: beta' is drawn from [0, B)."""
    return n * n << mask_bits


def key_bits(n: int, mask_bits: int = MASK_BITS) -> int:
    """Paillier size for curve order n: 2048 bits for secp256k1 (as advised).
    For the toy curve just enough for N > n^2 + B: 58 bits, two 29-bit primes."""
    if n.bit_length() > 64:
        return 2048
    need = (n * n + mask_bound(n, mask_bits)).bit_length() + 1  # N >= 2^(bits-1) > n^2 + B
    return need + need % 2  # even, so p and q get the same size


def check_key(N: int, n: int, mask_bits: int = MASK_BITS) -> None:
    """N must be bigger than n^2 + B, the largest value a*b + beta' can take."""
    if N <= n * n + mask_bound(n, mask_bits):
        need = (n * n + mask_bound(n, mask_bits)).bit_length()
        raise ValueError(f"Paillier N needs more than {need} bits for this n")


def _check_input(x: int, n: int) -> None:
    if not 0 <= x < n:
        raise ValueError("MtA inputs must be in [0, n-1]")


# The three steps on their own, without a channel, so tests and the
# visualizer can see every value.

def alice_encrypt(N: int, a: int, n: int) -> int:
    """Step 1 (Alice): c_A = Enc(a). Her key is checked once, at setup."""
    _check_input(a, n)
    return paillier.encrypt(N, a)


def bob_respond(N: int, c_A: int, b: int, n: int, mask: bool = True,
                mask_bits: int = MASK_BITS) -> tuple[int, int, int]:
    """Step 2 (Bob): returns (c_B, beta, beta_prime)."""
    check_key(N, n, mask_bits)
    _check_input(b, n)
    beta_prime = secrets.randbelow(mask_bound(n, mask_bits)) if mask else 0
    c_B = paillier.add(N, paillier.mul_const(N, c_A, b), paillier.encrypt(N, beta_prime))
    return c_B, -beta_prime % n, beta_prime


def alice_decrypt(key: Key, c_B: int, n: int) -> int:
    """Step 3 (Alice): alpha = Dec(c_B) mod n."""
    return paillier.decrypt(key, c_B) % n


def _show(show, step: str, **values) -> None:
    """Report a step to the show hook, if any (see protocol.py)."""
    if show is not None:
        show(step, values)


def mta_alice(channel, key: Key, a: int, n: int, show=None) -> int:
    """Alice's side. Returns alpha. Sends one message, receives one."""
    c_A = alice_encrypt(key.N, a, n)
    _show(show, "send c_A = Enc(a)", a=a, c_A=c_A)
    channel.send({"c_A": c_A})
    c_B = channel.recv()["c_B"]
    plain = paillier.decrypt(key, c_B)  # a*b + beta' as a whole number
    alpha = plain % n
    _show(show, "alpha = Dec(c_B) mod n", c_B=c_B, plain=plain, alpha=alpha)
    return alpha


def mta_bob(channel, N: int, b: int, n: int, mask: bool = True, show=None,
            mask_bits: int = MASK_BITS) -> int:
    """Bob's side. Returns beta. mask=False only for the experiment."""
    c_A = channel.recv()["c_A"]
    c_B, beta, beta_prime = bob_respond(N, c_A, b, n, mask, mask_bits)
    _show(show, "send c_B = c_A^b * Enc(beta'), keep beta = -beta' mod n",
          c_A=c_A, b=b, beta_prime=beta_prime, c_B=c_B, beta=beta)
    channel.send({"c_B": c_B})
    return beta


def recover_b(alpha: int, a: int, n: int) -> int:
    """The attack: without beta', alpha = a*b mod n, so b = alpha * a^-1.

    Alice knows a (for example her nonce share k1). If b is Bob's key share d2,
    she now has d = d1 + d2. With beta' the result is just a random number.
    """
    return alpha * pow(a, -1, n) % n
