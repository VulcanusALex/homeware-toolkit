"""SRP-6 (Secure Remote Password) client and verifier, pure stdlib.

Implements the variant used by Technicolor/Vantiva Homeware gateways
(Vodafone WiFi Hub / VCNT-I family), as documented by public research
(mysrp.py in benwaterson/technicolor-exploit):

  * RFC 5054 2048-bit group (g = 2);
  * SHA-256 as the hash;
  * SRP-6 legacy fixed multiplier k (NOT k = H(N, g) from SRP-6a) —
  * x = H(s, H(I ":" p)), M1 = H(H(N) xor H(g), H(I), s, A, B, K).

The fixed k is the value Homeware firmware ships; it is the SHA-256 of a
constant string baked into the firmware and is the same across devices.
"""

from __future__ import annotations

import hashlib
import secrets

# RFC 5054 2048-bit group prime
N_2048 = int(
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4"
    "A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF60"
    "95179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF"
    "747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B907"
    "8717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB37861"
    "60279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DB"
    "FBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73", 16)

G = 2

# Legacy SRP-6 multiplier shipped in Homeware firmware (replaces k = H(N, g)).
K_LEGACY = int("05b9e8ef059c6b32ea59fc1d322d37f04aa30bae5aa9003b8321e21ddb04e300", 16)

_HASH = hashlib.sha256


def _b2i(data: bytes) -> int:
    return int.from_bytes(data, "big")


def _i2b(value: int) -> bytes:
    length = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, "big")


def _H(*parts) -> int:
    h = _HASH()
    for part in parts:
        h.update(_i2b(part) if isinstance(part, int) else part)
    return int(h.hexdigest(), 16)


def _gen_x(salt: bytes, username: bytes, password: bytes) -> int:
    inner = _HASH(username + b":" + password).digest()
    return _H(salt, inner)


def make_verifier(username: bytes, password: bytes,
                  salt: bytes | None = None) -> tuple[bytes, int]:
    """Compute (salt, verifier) for a user — the server-side enrollment."""
    salt = salt if salt is not None else secrets.token_bytes(4)
    x = _gen_x(salt, username, password)
    return salt, pow(G, x, N_2048)


class Client:
    """SRP-6 client for the Homeware /authenticate handshake."""

    def __init__(self, username: bytes, password: bytes,
                 a: int | None = None) -> None:
        self.I = username
        self._p = password
        self.a = a if a is not None else secrets.randbits(256) | (1 << 255)
        self.A = pow(G, self.a, N_2048)
        self.K: bytes | None = None
        self.M1_secret: bytes | None = None
        self._hamk: int | None = None

    def public_ephemeral(self) -> bytes:
        return _i2b(self.A)

    def process_challenge(self, salt: bytes, B_bytes: bytes) -> bytes:
        """Compute the client proof M1; raises on unsafe server values."""
        s = _b2i(salt)
        B = _b2i(B_bytes)
        if B % N_2048 == 0:
            raise ValueError("unsafe SRP6 server ephemeral (B % N == 0)")
        u = _H(self.A, B)
        if u == 0:
            raise ValueError("unsafe SRP6 scrambling parameter (u == 0)")
        x = _gen_x(salt, self.I, self._p)
        v = pow(G, x, N_2048)
        S = pow((B - K_LEGACY * v) % N_2048, (self.a + u * x), N_2048)
        self.K = _HASH(_i2b(S)).digest()
        # M1 = H( H(N) xor H(g), H(I), s, A, B, K )
        hnxorg = bytes(aa ^ bb for aa, bb in zip(
            _HASH(_i2b(N_2048)).digest(), _HASH(_i2b(G)).digest()))
        h = _HASH()
        for part in (hnxorg, _HASH(self.I).digest(), salt,
                     _i2b(self.A), B_bytes, self.K):
            h.update(part)
        self.M1_secret = h.digest()
        self._hamk = _H(self.A, _b2i(self.M1_secret), _b2i(self.K))
        return self.M1_secret

    def verify_server(self, m2: bytes) -> bool:
        """Verify the server's proof H(A, M1, K)."""
        return self._hamk is not None and _b2i(m2) == self._hamk


class Server:
    """Server side of the same handshake (used by the simulator)."""

    def __init__(self, username: bytes, salt: bytes, verifier: int,
                 b: int | None = None) -> None:
        self.I = username
        self.salt = salt
        self.v = verifier
        self.b = b if b is not None else secrets.randbits(256) | (1 << 255)
        self.B = (K_LEGACY * self.v + pow(G, self.b, N_2048)) % N_2048
        self.K: bytes | None = None
        self.M1_expected: bytes | None = None

    def public_ephemeral(self) -> bytes:
        return _i2b(self.B)

    def process(self, A_bytes: bytes) -> tuple[bytes, bytes]:
        """Validate the client proof; returns (M1, M2) or raises."""
        A = _b2i(A_bytes)
        if A % N_2048 == 0:
            raise ValueError("unsafe SRP6 client ephemeral (A % N == 0)")
        u = _H(A, self.B)
        if u == 0:
            raise ValueError("unsafe SRP6 scrambling parameter (u == 0)")
        S = pow((A * pow(self.v, u, N_2048)) % N_2048, self.b, N_2048)
        self.K = _HASH(_i2b(S)).digest()
        hnxorg = bytes(aa ^ bb for aa, bb in zip(
            _HASH(_i2b(N_2048)).digest(), _HASH(_i2b(G)).digest()))
        h = _HASH()
        for part in (hnxorg, _HASH(self.I).digest(), self.salt,
                     A_bytes, _i2b(self.B), self.K):
            h.update(part)
        self.M1_expected = h.digest()
        m2 = _H(A, _b2i(self.M1_expected), _b2i(self.K))
        return self.M1_expected, _i2b(m2)
