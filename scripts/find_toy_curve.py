"""Search for a small curve y^2 = x^3 + 7 (mod p) whose group order is prime.

    python scripts/find_toy_curve.py [max_p]

Counts the points by brute force (fine for small p) and prints every p in
[200, max_p] with a prime order n > 200. Curves with n == p are flagged:
those "anomalous" curves are weak and should not be used even as a toy.
"""
import sys


def is_prime(n: int) -> bool:
    return n > 1 and all(n % i for i in range(2, int(n ** 0.5) + 1))


def count_points(p: int, a: int = 0, b: int = 7) -> int:
    squares: dict[int, int] = {}
    for y in range(p):
        squares[y * y % p] = squares.get(y * y % p, 0) + 1
    return 1 + sum(squares.get((x ** 3 + a * x + b) % p, 0) for x in range(p))


def smallest_point(p: int, a: int = 0, b: int = 7) -> tuple[int, int]:
    for x in range(p):
        for y in range(p):
            if (y * y - (x ** 3 + a * x + b)) % p == 0:
                return x, y
    raise ValueError("no point")


def main(max_p: int = 400) -> None:
    for p in range(200, max_p + 1):
        if not is_prime(p):
            continue
        n = count_points(p)
        if is_prime(n) and n > 200:
            note = "  (anomalous: n == p, avoid)" if n == p else ""
            print(f"p={p} n={n} G={smallest_point(p)}{note}")


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 400)
