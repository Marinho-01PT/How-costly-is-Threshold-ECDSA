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
