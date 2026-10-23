import secrets

import pytest

from twoparty import mta, paillier
from twoparty.ec import SECP256K1, TOY

TOY_N = TOY.n
SECP_N = SECP256K1.n


def local_mta(key, a, b, n, mask=True):
    """All three steps in one place, no network. Returns (alpha, beta)."""
    c_A = mta.alice_encrypt(key.N, a, n)
    c_B, beta, _ = mta.bob_respond(key.N, c_A, b, n, mask)
    return mta.alice_decrypt(key, c_B, n), beta


def test_parameters_from_the_mail():
    assert mta.mask_bound(TOY_N) == TOY_N**2 * 2**40
    assert mta.key_bits(SECP_N) == 2048
    # Toy curve: n^2 + B has 57 bits, so N needs 58 (two 29-bit primes, "about 30").
    assert (TOY_N**2 + mta.mask_bound(TOY_N)).bit_length() == 57
    assert mta.key_bits(TOY_N) == 58


def test_study_mode_parameters():
    """mask_bits = 4 keeps every number small: B = 16 n^2, N with 22 bits."""
    assert mta.mask_bound(TOY_N, 4) == 16 * TOY_N**2
    assert mta.key_bits(TOY_N, 4) == 22
    key = paillier.keygen(mta.key_bits(TOY_N, 4))
    mta.check_key(key.N, TOY_N, 4)
    a, b = 17, 42
    c_B, beta, beta_prime = mta.bob_respond(key.N, mta.alice_encrypt(key.N, a, TOY_N), b,
                                            TOY_N, mask_bits=4)
    assert beta_prime < 16 * TOY_N**2
    assert (mta.alice_decrypt(key, c_B, TOY_N) + beta) % TOY_N == a * b % TOY_N


def test_key_sizes_are_big_enough(toy_key, secp_key):
    mta.check_key(toy_key.N, TOY_N)
    mta.check_key(secp_key.N, SECP_N)


def test_too_small_key_is_rejected(toy_key):
    with pytest.raises(ValueError):
        mta.check_key(paillier.keygen(40).N, TOY_N)
    with pytest.raises(ValueError):  # Bob checks too, before every answer
        mta.bob_respond(paillier.keygen(40).N, 1, 1, TOY_N)
    with pytest.raises(ValueError):  # 58 bits are far too few for secp256k1
        mta.check_key(toy_key.N, SECP_N)


def test_inputs_out_of_range(toy_key):
    for x in (-1, TOY_N):
        with pytest.raises(ValueError):
            mta.alice_encrypt(toy_key.N, x, TOY_N)
        with pytest.raises(ValueError):
            mta.bob_respond(toy_key.N, 1, x, TOY_N)


def test_shares_add_up_toy(toy_key):
    for _ in range(1000):
        a, b = secrets.randbelow(TOY_N), secrets.randbelow(TOY_N)
        alpha, beta = local_mta(toy_key, a, b, TOY_N)
        assert (alpha + beta) % TOY_N == a * b % TOY_N


@pytest.mark.parametrize("a, b", [(0, 0), (0, 5), (5, 0), (1, 1), (TOY_N - 1, TOY_N - 1)])
def test_edge_cases_toy(toy_key, a, b):
    alpha, beta = local_mta(toy_key, a, b, TOY_N)
    assert (alpha + beta) % TOY_N == a * b % TOY_N


def test_shares_add_up_secp(secp_key):
    a, b = secrets.randbelow(SECP_N), secrets.randbelow(SECP_N)
    alpha, beta = local_mta(secp_key, a, b, SECP_N)
    assert (alpha + beta) % SECP_N == a * b % SECP_N


def test_no_wraparound_mod_N(toy_key):
    """Biggest possible plaintext a*b + beta' still fits below N."""
    n = TOY_N
    assert (n - 1) ** 2 + mta.mask_bound(n) - 1 < toy_key.N


def test_shares_look_random(toy_key):
    """Same inputs, fresh beta' each time: alpha changes."""
    alphas = {local_mta(toy_key, 7, 11, TOY_N)[0] for _ in range(50)}
    assert len(alphas) > 1


def test_over_the_network_toy(run_pair, toy_key):
    pairs = [(secrets.randbelow(TOY_N), secrets.randbelow(TOY_N)) for _ in range(30)]
    alphas, betas, stats = run_pair(
        lambda ch: [mta.mta_alice(ch, toy_key, a, TOY_N) for a, _ in pairs],
        lambda ch: [mta.mta_bob(ch, toy_key.N, b, TOY_N) for _, b in pairs],
    )
    for (a, b), alpha, beta in zip(pairs, alphas, betas):
        assert (alpha + beta) % TOY_N == a * b % TOY_N
    # One message each way per MtA.
    assert stats["sent_msgs"] == stats["recv_msgs"] == len(pairs)


def test_over_the_network_secp(run_pair, secp_key):
    a, b = secrets.randbelow(SECP_N), secrets.randbelow(SECP_N)
    alpha, beta, stats = run_pair(
        lambda ch: mta.mta_alice(ch, secp_key, a, SECP_N),
        lambda ch: mta.mta_bob(ch, secp_key.N, b, SECP_N),
    )
    assert (alpha + beta) % SECP_N == a * b % SECP_N
    assert stats["sent_msgs"] == stats["recv_msgs"] == 1


# The experiment: Bob leaves out beta'.

def test_without_mask_alice_sees_the_product(toy_key):
    a, b = 17, 42
    c_A = mta.alice_encrypt(toy_key.N, a, TOY_N)
    c_B, beta, beta_prime = mta.bob_respond(toy_key.N, c_A, b, TOY_N, mask=False)
    assert beta_prime == 0 and beta == 0
    assert paillier.decrypt(toy_key, c_B) == a * b  # the exact product, not even mod n


@pytest.mark.parametrize("curve", [TOY, SECP256K1], ids=lambda c: c.name)
def test_attack_recovers_bobs_key_share(curve, toy_key, secp_key):
    key = toy_key if curve is TOY else secp_key
    n = curve.n
    k1 = secrets.randbelow(n - 1) + 1   # Alice's nonce share, she knows it
    d2 = secrets.randbelow(n - 1) + 1   # Bob's key share, secret
    alpha, _ = local_mta(key, k1, d2, n, mask=False)
    assert mta.recover_b(alpha, k1, n) == d2


def test_attack_fails_with_mask_secp(secp_key):
    k1 = secrets.randbelow(SECP_N - 1) + 1
    d2 = secrets.randbelow(SECP_N - 1) + 1
    alpha, _ = local_mta(secp_key, k1, d2, SECP_N)
    assert mta.recover_b(alpha, k1, SECP_N) != d2


def test_attack_with_mask_is_just_guessing_toy(toy_key):
    """With beta', the 'recovered' d2 is right only by chance (about 1 in 313)."""
    hits = 0
    for _ in range(300):
        k1 = secrets.randbelow(TOY_N - 1) + 1
        d2 = secrets.randbelow(TOY_N - 1) + 1
        alpha, _ = local_mta(toy_key, k1, d2, TOY_N)
        hits += mta.recover_b(alpha, k1, TOY_N) == d2
    assert hits < 15  # expected about 1
