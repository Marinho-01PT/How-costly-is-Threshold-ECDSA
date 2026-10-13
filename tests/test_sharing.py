from twoparty.curve import N, rand_scalar
from twoparty.sharing import combine, share


def test_shares_add_up():
    d = rand_scalar()
    d1, d2 = share(d)
    assert combine(d1, d2) == d


def test_shares_differ_between_runs():
    d = rand_scalar()
    assert share(d)[0] != share(d)[0]


def test_shares_in_range():
    d1, d2 = share(rand_scalar())
    assert 0 <= d1 < N and 0 <= d2 < N


def test_toy_modulus():
    n = 313
    d1, d2 = share(42, n=n)
    assert combine(d1, d2, n=n) == 42 and 0 <= d2 < n


def test_given_d1():
    assert share(42, n=313, d1=100) == (100, 255)


def test_one_share_fits_every_secret():
    """For a fixed d1, every secret d has exactly one matching d2:
    d1 alone says nothing about d."""
    n, d1 = 313, 100
    d2s = {share(d, n=n, d1=d1)[1] for d in range(n)}
    assert len(d2s) == n
