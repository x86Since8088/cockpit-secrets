"""twofish_pure — Twofish (128/192/256-bit keys) in pure Python.

WHY THIS FILE EXISTS
--------------------
Password Safe v3 encrypts with Twofish and nothing else. `python3-botan`
(Botan 3.10) is the primary provider on this host and is what `psafe3.py`
reaches for first — a maintained, audited, general-purpose C++ library beats
anything written here. This module is the FALLBACK for a host where that
package is absent, and it exists so that "no Botan" degrades to "slower" rather
than to "cannot open the safe".

docs/UPSTREAM-REVIEW.md §3.3 rules out the alternative — a PyPI `twofish`
wheel — and it is right to: an unpinned, unaudited binary wheel in the one
process that holds every credential we own is a worse trade than 400 lines of
readable Python whose output is checked against the published vectors on every
test run.

BUILT FROM THE SPECIFICATION, NOT FROM A SUMMARY
------------------------------------------------
Everything here comes from the Twofish paper (Schneier, Kelsey, Whiting,
Wagner, Hall, Ferguson — "Twofish: A 128-Bit Block Cipher", §4):

  - §4.3.5  the q0/q1 permutations, BUILT from the four 4-bit t-tables rather
            than transcribed as two 256-byte blobs. 128 nibbles that can be
            eyeballed against the paper beat 512 bytes that cannot.
  - §4.3.2  the function h, including the two extra q/xor layers that only
            192- and 256-bit keys use.
  - §4.3.1  the key schedule: M_e/M_o, the RS-derived S vector *in reverse
            order*, and the 40 round subkeys.
  - §4.1    the 16-round Feistel network with its 1-bit rotations and the
            input/output whitening.

The two GF(2^8) fields are different and mixing them is the classic way to get
an implementation that looks right and interoperates with nothing:
    MDS uses v(x) = x^8 + x^6 + x^5 + x^3 + 1   (0x169)
    RS  uses w(x) = x^8 + x^6 + x^3 + x^2 + 1   (0x14D)

VERIFICATION
------------
`tests/vectors/twofish_ecb.json` holds the published ECB known-answer vectors
(Schneier's `ecb_ival.txt` plus Botan's `twofish.vec`), and BOTH providers —
this one and Botan's — are run against all of them. Round-tripping through our
own code proves nothing (docs/UPSTREAM-REVIEW.md §4, bad practice #20); the
vectors are foreign evidence and they are the reason to believe this file.

HONEST LIMITATIONS — read before trusting this for anything but PWS3
--------------------------------------------------------------------
1. **Not constant time.** Every S-box and MDS access is a Python list index on
   a secret-dependent value, so cache and interpreter timing leak the same way
   any table-driven Twofish does (Botan's included). This is acceptable HERE
   because the adversaries in docs/THREAT-MODEL.md do not include a local
   cache-timing observer, and because a root-equivalent local attacker — who is
   the only one positioned to measure it — is already explicitly out of scope.
   Do not lift this module into a context where that changes.
2. **Key material cannot be wiped.** Round keys are Python ints in lists;
   `clear()` overwrites the lists, but CPython has already had every
   opportunity to copy those ints elsewhere on the heap. This mirrors the
   honesty in `backends/base.py`'s `Secret`: it shrinks the window, it does not
   close it.
3. **Slow.** Measured on edt1 (Python 3.14.4): ~26 us per 16-byte block, which
   works out at ~0.5 MiB/s through PWS3's CBC, against ~40 MiB/s read and
   ~5 MiB/s write for Botan. Key setup is ~0.35 ms.

   The operational consequence is worth stating rather than discovering: a safe
   at `Limits.MAX_SAFE_BYTES` (128 MiB) takes about four minutes to decrypt on
   this path. Real Password Safe databases are kilobytes — the format's own
   spec advises staying under 100 MB *total* — so this is a ceiling, not a
   normal case, and lowering `MAX_SAFE_BYTES` for the fallback would be
   inventing a policy rather than reporting a fact. `psafe3.py` names the
   provider it used in `probe()` so an operator can see when a slow open is
   this and not something else.

Licence: GPL-3.0 — see ../LICENSE.
"""

__all__ = ["Twofish", "BLOCK_SIZE", "KEY_SIZES"]

#: Twofish is a 128-bit block cipher. Not configurable; PWS3 depends on it.
BLOCK_SIZE = 16
#: The three legal key lengths in bytes. Botan's own keyspec on this host is
#: (min 16, max 32, modulo 8), i.e. exactly these; refusing anything else keeps
#: the two providers interchangeable instead of subtly divergent.
KEY_SIZES = (16, 24, 32)

_MASK32 = 0xFFFFFFFF


# ===========================================================================
# GF(2^8) arithmetic — two different fields, deliberately spelled out
# ===========================================================================

#: MDS field modulus, v(x) = x^8 + x^6 + x^5 + x^3 + 1.
_MDS_POLY = 0x169
#: RS field modulus, w(x) = x^8 + x^6 + x^3 + x^2 + 1.
_RS_POLY = 0x14D


def _gf_mul(a, b, poly):
    """Carry-less multiply in GF(2^8) modulo `poly`.

    Used only at import time and at key-schedule time to build tables, so the
    shift-and-xor form is chosen for legibility over speed.
    """
    result = 0
    while b:
        if b & 1:
            result ^= a
        b >>= 1
        a <<= 1
        if a & 0x100:
            a ^= poly
    return result & 0xFF


# ===========================================================================
# q0 and q1 — built from the 4-bit t-tables of §4.3.5
# ===========================================================================

# Each q permutation is defined by four 4-bit permutations. Transcribing these
# 64 nibbles per q is checkable against the paper by eye; transcribing the
# resulting 256-byte tables is not, and a single wrong byte would produce a
# cipher that fails the vectors with no clue as to where.
_T_Q0 = (
    (0x8, 0x1, 0x7, 0xD, 0x6, 0xF, 0x3, 0x2, 0x0, 0xB, 0x5, 0x9, 0xE, 0xC, 0xA, 0x4),
    (0xE, 0xC, 0xB, 0x8, 0x1, 0x2, 0x3, 0x5, 0xF, 0x4, 0xA, 0x6, 0x7, 0x0, 0x9, 0xD),
    (0xB, 0xA, 0x5, 0xE, 0x6, 0xD, 0x9, 0x0, 0xC, 0x8, 0xF, 0x3, 0x2, 0x4, 0x7, 0x1),
    (0xD, 0x7, 0xF, 0x4, 0x1, 0x2, 0x6, 0xE, 0x9, 0xB, 0x3, 0x0, 0x8, 0x5, 0xC, 0xA),
)
_T_Q1 = (
    (0x2, 0x8, 0xB, 0xD, 0xF, 0x7, 0x6, 0xE, 0x3, 0x1, 0x9, 0x4, 0x0, 0xA, 0xC, 0x5),
    (0x1, 0xE, 0x2, 0xB, 0x4, 0xC, 0x3, 0x7, 0x6, 0xD, 0xA, 0x5, 0xF, 0x9, 0x0, 0x8),
    (0x4, 0xC, 0x7, 0x5, 0x1, 0x6, 0x9, 0xA, 0x0, 0xE, 0xD, 0x8, 0x2, 0xB, 0x3, 0xF),
    (0xB, 0x9, 0x5, 0x1, 0xC, 0x3, 0xD, 0xE, 0x6, 0x4, 0x7, 0xF, 0x2, 0x0, 0x8, 0xA),
)


def _build_q(t):
    """The q permutation of §4.3.5, expanded to a 256-entry table.

        a0,b0 = x>>4, x&15
        a1 = a0 ^ b0
        b1 = a0 ^ ROR4(b0,1) ^ (8*a0 mod 16)
        a2,b2 = t0[a1], t1[b1]
        a3 = a2 ^ b2
        b3 = a2 ^ ROR4(b2,1) ^ (8*a2 mod 16)
        a4,b4 = t2[a3], t3[b3]
        q(x) = 16*b4 + a4
    """
    t0, t1, t2, t3 = t
    table = []
    for x in range(256):
        a0, b0 = x >> 4, x & 0xF
        a1 = a0 ^ b0
        b1 = (a0 ^ ((b0 >> 1) | ((b0 << 3) & 0xF)) ^ ((a0 << 3) & 0xF)) & 0xF
        a2, b2 = t0[a1], t1[b1]
        a3 = a2 ^ b2
        b3 = (a2 ^ ((b2 >> 1) | ((b2 << 3) & 0xF)) ^ ((a2 << 3) & 0xF)) & 0xF
        a4, b4 = t2[a3], t3[b3]
        table.append((b4 << 4) | a4)
    return tuple(table)


_Q0 = _build_q(_T_Q0)
_Q1 = _build_q(_T_Q1)


# ===========================================================================
# MDS — 4x4 over GF(2^8)/v(x), precomputed one table per input byte position
# ===========================================================================

_MDS_MATRIX = (
    (0x01, 0xEF, 0x5B, 0x5B),
    (0x5B, 0xEF, 0xEF, 0x01),
    (0xEF, 0x5B, 0x01, 0xEF),
    (0xEF, 0x01, 0xEF, 0x5B),
)


def _build_mds_column(col):
    """Table of `MDS * (0,..,b,..,0)` packed little-endian, for input byte `col`.

    With one of these per column, the matrix multiply in h() becomes four
    lookups and three XORs instead of sixteen field multiplications.
    """
    table = []
    for b in range(256):
        word = 0
        for row in range(4):
            word |= _gf_mul(_MDS_MATRIX[row][col], b, _MDS_POLY) << (8 * row)
        table.append(word)
    return tuple(table)


_MDS0 = _build_mds_column(0)
_MDS1 = _build_mds_column(1)
_MDS2 = _build_mds_column(2)
_MDS3 = _build_mds_column(3)


# ===========================================================================
# RS — 4x8 over GF(2^8)/w(x), used once per 64 bits of key
# ===========================================================================

_RS_MATRIX = (
    (0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E),
    (0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5),
    (0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19),
    (0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03),
)


def _rs_encode(chunk8):
    """Reed-Solomon-reduce 8 key bytes to the 32-bit S-box key word S_i."""
    word = 0
    for row in range(4):
        acc = 0
        for col in range(8):
            acc ^= _gf_mul(_RS_MATRIX[row][col], chunk8[col], _RS_POLY)
        word |= acc << (8 * row)
    return word


# ===========================================================================
# helpers
# ===========================================================================

def _rol32(x, n):
    return ((x << n) | (x >> (32 - n))) & _MASK32


def _ror32(x, n):
    return ((x >> n) | (x << (32 - n))) & _MASK32


def _words_le(data):
    """Bytes -> little-endian 32-bit words, the byte order Twofish specifies."""
    return [int.from_bytes(data[i:i + 4], "little")
            for i in range(0, len(data), 4)]


#: The q-permutation chain of §4.3.2, one tuple per input byte position. Each
#: tuple lists the q's in APPLICATION order — innermost first — as the key
#: words l3, l2, l1, l0 are XORed in; the comment above each row is the same
#: thing written as the nested expression from the paper. Splitting h this way
#: is not a micro-optimisation, it is what makes the g() tables correct (see
#: `_h_byte`).
_H_CHAIN = (
    # position 0:  q1[q0[q0[ q1[ q1[y] ^l3 ] ^l2 ] ^l1] ^l0]
    (_Q1, _Q1, _Q0, _Q0, _Q1),
    # position 1:  q0[q0[q1[ q1[ q0[y] ^l3 ] ^l2 ] ^l1] ^l0]
    (_Q0, _Q1, _Q1, _Q0, _Q0),
    # position 2:  q1[q1[q0[ q0[ q0[y] ^l3 ] ^l2 ] ^l1] ^l0]
    (_Q0, _Q0, _Q0, _Q1, _Q1),
    # position 3:  q0[q1[q1[ q0[ q1[y] ^l3 ] ^l2 ] ^l1] ^l0]
    (_Q1, _Q0, _Q1, _Q1, _Q0),
)


def _h_byte(pos, y, L):
    """The per-byte q/XOR chain of h, BEFORE the MDS multiply.

    h treats its four input bytes independently until the MDS matrix mixes
    them, and the whole point of separating this out is that `Twofish.__init__`
    can then tabulate `MDS_j[_h_byte(j, b, S)]` per byte position and rebuild
    g() as four lookups and three XORs.

    That decomposition has to be done HERE and not by calling `_h(b << 8j)`:
    h(b<<8) is the real answer XORed with the MDS contribution of three ZERO
    bytes, so tabulating it that way yields a cipher that encrypts and decrypts
    perfectly consistently and disagrees with every other implementation on
    earth. This file made exactly that mistake once; the published vectors
    caught it, which is the argument for having them.
    """
    chain = _H_CHAIN[pos]
    shift = 8 * pos
    k = len(L)
    # k == 2 (a 128-bit key) skips both of these; the "all cases" step below
    # then runs straight off the raw input byte, which is what §4.3.2 says.
    if k == 4:
        y = chain[0][y] ^ ((L[3] >> shift) & 0xFF)
    if k >= 3:
        y = chain[1][y] ^ ((L[2] >> shift) & 0xFF)
    y = chain[3][chain[2][y] ^ ((L[1] >> shift) & 0xFF)]
    return chain[4][y ^ ((L[0] >> shift) & 0xFF)]


def _h(x, L):
    """The function h of §4.3.2. `L` is a list of k 32-bit words, k in 2..4.

    Called with M_e / M_o during the key schedule and with the S vector for g.
    The extra layers for k>=3 and k==4 are the ones that make a 192- or
    256-bit key produce different output from a 128-bit key with the same
    low words; omitting them yields a cipher that passes the 128-bit vectors
    and fails everything else.
    """
    return (_MDS0[_h_byte(0, x & 0xFF, L)]
            ^ _MDS1[_h_byte(1, (x >> 8) & 0xFF, L)]
            ^ _MDS2[_h_byte(2, (x >> 16) & 0xFF, L)]
            ^ _MDS3[_h_byte(3, (x >> 24) & 0xFF, L)])


# ===========================================================================
# the cipher
# ===========================================================================

class Twofish:
    """One Twofish key, ECB block operations only.

    Deliberately raw: no mode, no padding, no IV. `psafe3.py` drives CBC
    itself because Password Safe v3's CBC has no padding scheme of its own —
    fields are already block-aligned by the format — and a library mode that
    quietly added PKCS#7 would corrupt every file we wrote.

    The API is the same shape as `botan3.BlockCipher` so that `psafe3.py` can
    hold either provider behind one adapter and the vectors can exercise both
    through the same code path.
    """

    __slots__ = ("_k", "_s0", "_s1", "_s2", "_s3", "_cleared")

    #: `rho` of §4.3.1: the constant that spreads the round counter across all
    #: four bytes of h's input.
    _RHO = 0x01010101

    def __init__(self, key):
        if isinstance(key, (bytearray, memoryview)):
            key = bytes(key)
        if not isinstance(key, bytes):
            raise TypeError("Twofish key must be bytes")
        if len(key) not in KEY_SIZES:
            # No silent zero-padding to the next legal size. A caller that
            # hands over 20 bytes has a bug, and padding it would hide the bug
            # behind a key nobody can reproduce.
            raise ValueError("Twofish key must be 16, 24 or 32 bytes")

        k = len(key) // 8
        m_even = []
        m_odd = []
        s_words = []
        for i in range(k):
            chunk = key[8 * i:8 * i + 8]
            m_even.append(int.from_bytes(chunk[0:4], "little"))
            m_odd.append(int.from_bytes(chunk[4:8], "little"))
            s_words.append(_rs_encode(chunk))
        # §4.3.1: "S = (S_{k-1}, ..., S_1, S_0)" — REVERSED. The reference C
        # code writes sboxKeys[k64Cnt-1-i] for the same reason. Getting this
        # backwards gives a cipher that is self-consistent and interoperates
        # with nothing.
        s_words.reverse()

        # 40 round subkeys: K_0..K_7 are the whitening keys, K_8..K_39 the
        # per-round keys.
        subkeys = []
        for i in range(20):
            a = _h((2 * i * self._RHO) & _MASK32, m_even)
            b = _rol32(_h(((2 * i + 1) * self._RHO) & _MASK32, m_odd), 8)
            subkeys.append((a + b) & _MASK32)
            subkeys.append(_rol32((a + 2 * b) & _MASK32, 9))
        self._k = subkeys

        # g(X) = h(X, S). S is fixed for the life of the key, so expand it once
        # into four 256-entry tables: g becomes four lookups and three XORs.
        # 1024 chain evaluations here buys ~10x on every block afterwards,
        # which matters because a PWS3 save re-encrypts the whole database.
        # NOTE the per-byte form: `_h(b << 8*j)` would fold in the MDS
        # contribution of three zero bytes. See `_h_byte`.
        self._s0 = tuple(_MDS0[_h_byte(0, b, s_words)] for b in range(256))
        self._s1 = tuple(_MDS1[_h_byte(1, b, s_words)] for b in range(256))
        self._s2 = tuple(_MDS2[_h_byte(2, b, s_words)] for b in range(256))
        self._s3 = tuple(_MDS3[_h_byte(3, b, s_words)] for b in range(256))
        self._cleared = False

    # -- introspection, so callers can log which provider they got ---------

    @staticmethod
    def block_size():
        return BLOCK_SIZE

    @staticmethod
    def algo_name():
        return "Twofish"

    # -- the Feistel network -----------------------------------------------

    def _g(self, x):
        """g(X) = h(X, S), via the precomputed per-byte tables."""
        return (self._s0[x & 0xFF]
                ^ self._s1[(x >> 8) & 0xFF]
                ^ self._s2[(x >> 16) & 0xFF]
                ^ self._s3[(x >> 24) & 0xFF])

    def encrypt_block(self, block):
        """One 16-byte block, ECB. Returns bytes."""
        if self._cleared:
            raise ValueError("this Twofish key has been cleared")
        if len(block) != BLOCK_SIZE:
            raise ValueError("Twofish block must be exactly 16 bytes")
        k = self._k
        g = self._g
        r0, r1, r2, r3 = _words_le(block)
        # input whitening
        r0 ^= k[0]
        r1 ^= k[1]
        r2 ^= k[2]
        r3 ^= k[3]
        for rnd in range(16):
            t0 = g(r0)
            t1 = g(_rol32(r1, 8))
            f0 = (t0 + t1 + k[2 * rnd + 8]) & _MASK32
            f1 = (t0 + 2 * t1 + k[2 * rnd + 9]) & _MASK32
            # the 1-bit rotations are what stop the round function from being
            # a pure Feistel and are easy to drop by accident
            n2 = _ror32(r2 ^ f0, 1)
            n3 = _rol32(r3, 1) ^ f1
            r0, r1, r2, r3 = n2, n3, r0, r1
        # output whitening, which also undoes the final swap
        out = ((r2 ^ k[4]).to_bytes(4, "little")
               + (r3 ^ k[5]).to_bytes(4, "little")
               + (r0 ^ k[6]).to_bytes(4, "little")
               + (r1 ^ k[7]).to_bytes(4, "little"))
        return out

    def decrypt_block(self, block):
        """One 16-byte block, ECB. Returns bytes."""
        if self._cleared:
            raise ValueError("this Twofish key has been cleared")
        if len(block) != BLOCK_SIZE:
            raise ValueError("Twofish block must be exactly 16 bytes")
        k = self._k
        g = self._g
        c0, c1, c2, c3 = _words_le(block)
        # undo the output whitening AND the final swap in one step
        r0 = c2 ^ k[6]
        r1 = c3 ^ k[7]
        r2 = c0 ^ k[4]
        r3 = c1 ^ k[5]
        for rnd in range(15, -1, -1):
            n0, n1 = r2, r3
            t0 = g(n0)
            t1 = g(_rol32(n1, 8))
            f0 = (t0 + t1 + k[2 * rnd + 8]) & _MASK32
            f1 = (t0 + 2 * t1 + k[2 * rnd + 9]) & _MASK32
            n2 = _rol32(r0, 1) ^ f0
            n3 = _ror32(r1 ^ f1, 1)
            r0, r1, r2, r3 = n0, n1, n2, n3
        return ((r0 ^ k[0]).to_bytes(4, "little")
                + (r1 ^ k[1]).to_bytes(4, "little")
                + (r2 ^ k[2]).to_bytes(4, "little")
                + (r3 ^ k[3]).to_bytes(4, "little"))

    # -- multi-block convenience, same shape as botan3.BlockCipher ---------

    def encrypt(self, data):
        """ECB-encrypt a whole number of blocks. Returns bytes."""
        if len(data) % BLOCK_SIZE:
            raise ValueError("input must be a multiple of the block size")
        return b"".join(self.encrypt_block(bytes(data[i:i + BLOCK_SIZE]))
                        for i in range(0, len(data), BLOCK_SIZE))

    def decrypt(self, data):
        """ECB-decrypt a whole number of blocks. Returns bytes."""
        if len(data) % BLOCK_SIZE:
            raise ValueError("input must be a multiple of the block size")
        return b"".join(self.decrypt_block(bytes(data[i:i + BLOCK_SIZE]))
                        for i in range(0, len(data), BLOCK_SIZE))

    # -- lifetime ----------------------------------------------------------

    def clear(self):
        """Best-effort scrub of the expanded key (I14).

        Honest about what this is: the subkeys and S-box tables are Python
        ints inside tuples/lists, and the interpreter has already been free to
        copy them. Rebinding to zeros removes OUR references so the objects
        become collectable, and makes any use-after-clear an immediate error
        instead of a silent wrong answer. It does not overwrite whatever the
        allocator handed those ints. `backends/base.py` makes the same
        admission about `Secret`; the real mitigation is that this helper lives
        for one operation.
        """
        if not self._cleared:
            self._k = [0] * 40
            self._s0 = self._s1 = self._s2 = self._s3 = (0,) * 256
            self._cleared = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.clear()
        return False

    def __repr__(self):
        # Never the key, never a derived word — this object is going to end up
        # interpolated into a diagnostic sooner or later (I15).
        return "<Twofish pure %s>" % ("cleared" if self._cleared else "keyed")
