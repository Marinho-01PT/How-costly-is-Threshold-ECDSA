"""Building blocks and their variants: one Config picks one variant per row.

The rows are the table "Building blocks and their implementations" from our
protocol sheet. Every field below is one row; its first value is the variant
we started with, so Config() is exactly the original protocol.

    curve        how the protocol does point arithmetic
    bignum       which library computes the big Paillier numbers
    paillier_dec how Alice decrypts
    paillier_enc how both parties encrypt (CRT only works for Alice, who has p, q)
    paillier_bits size of N
    wire         how messages travel: JSON text or a compact binary format
    mask         True: normal MtA with beta'. False: the experiment without beta'
    mta          "separate": every MtA sends its own Enc(a) (4 per signature).
                 "reuse": Enc(d1) once at setup, Enc(k1) once per signature
                 for both MtAs with k1. Alice sends 2 ciphertexts instead of 4.
    flow         "sequential": one message per step (14 per signature).
                 "batched": everything that can travel together does (4).

The network row (localhost, Docker, two devices over Wi-Fi) is chosen by
where Bob runs, not here.
"""
from dataclasses import asdict, dataclass, fields, replace

# One entry per building block: (field, title, variants, planned variants).
# The UI and the benchmark matrix are built from this list.
ROWS = [
    ("curve", "Curve arithmetic in the protocol", ["pure", "libsecp256k1"], []),
    ("bignum", "Big-number arithmetic", ["int", "gmpy2"], []),
    ("paillier_dec", "Paillier decryption", ["naive", "crt"], []),
    ("paillier_enc", "Paillier encryption", ["naive", "crt", "precomputed"], []),
    ("paillier_bits", "Paillier key size", [2048, 3072], []),
    ("wire", "Message format", ["json", "binary"], []),
    ("mask", "Safety experiment (beta' in MtA)", [True, False], []),
    ("mta", "Use of MtA", ["separate", "reuse"], []),
    ("flow", "Message flow", ["sequential", "batched"], []),
]

LABELS = {
    "pure": "pure Python", "libsecp256k1": "libsecp256k1",
    "int": "Python int", "gmpy2": "gmpy2 (GMP)",
    "naive": "naive", "crt": "Chinese remainder theorem",
    "precomputed": "precomputed r^N (offline/online)",
    "json": "JSON, decimal text", "binary": "binary",
    True: "with beta'", False: "without beta' (key share leaks)",
    "separate": "4 separate MtAs", "reuse": "Enc(d1) once, Enc(k1) reused",
    "sequential": "one message per step (14)", "batched": "batched (4)",
}


@dataclass(frozen=True)
class Config:
    curve: str = "pure"
    bignum: str = "int"
    paillier_dec: str = "naive"
    paillier_enc: str = "naive"
    paillier_bits: int = 2048
    wire: str = "json"
    mask: bool = True
    mta: str = "separate"
    flow: str = "sequential"

    def __post_init__(self):
        for name, _, variants, _ in ROWS:
            if name in self.__dataclass_fields__ and getattr(self, name) not in variants:
                raise ValueError(f"{name} must be one of {variants}, not {getattr(self, name)!r}")
        if self.bignum == "gmpy2":
            try:
                import gmpy2  # noqa: F401
            except ImportError as exc:
                raise ValueError("bignum=gmpy2 needs: pip install gmpy2") from exc

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict | None) -> "Config":
        names = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in (d or {}).items() if k in names})

    def label(self) -> str:
        """Short name: only the rows that differ from the original protocol."""
        base = Config()
        diff = [f"{f.name}={getattr(self, f.name)}" for f in fields(self)
                if getattr(self, f.name) != getattr(base, f.name)]
        return ",".join(diff) or "original"

    def check_curve(self, curve_name: str) -> None:
        if self.curve == "libsecp256k1" and curve_name != "secp256k1":
            raise ValueError("curve=libsecp256k1 only works on secp256k1")


def variants_one_at_a_time() -> list[Config]:
    """The original protocol, then every other variant on its own.

    This answers "what does each building block change?". The experiment
    without beta' is left out: it is about safety, not speed.
    """
    out = [Config()]
    for name, _, variants, _ in ROWS:
        if name not in Config.__dataclass_fields__ or name == "mask":
            continue
        for v in variants[1:]:
            out.append(replace(Config(), **{name: v}))
    return out


def fastest() -> Config:
    """Every speed-up together (2048-bit key, as advised)."""
    return Config(curve="libsecp256k1", bignum="gmpy2", paillier_dec="crt",
                  paillier_enc="precomputed", wire="binary", mta="reuse", flow="batched")
