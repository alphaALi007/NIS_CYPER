"""
Classical building blocks and the custom cipher.

Custom cipher  =  Stage 1: Vigenere substitution  (key >= 10 letters)
                  Stage 2: Rail Fence transposition (depth >= 2)

    ENCRYPT:  C = RailFence_d( Vigenere_K( P ) )
    DECRYPT:  P = Vigenere_K^-1( RailFence_d^-1( C ) )

All routines are pure Python and run in O(n) time for an n-letter message.
"""
from typing import List

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
MIN_KEY_LEN = 10


# ----------------------------------------------------------------- helpers
def normalize(text: str) -> str:
    """Upper-case the text and keep only the letters A-Z (spaces, digits and
    punctuation are removed). The cipher works on this normalised alphabet."""
    return "".join(ch for ch in text.upper() if "A" <= ch <= "Z")


def _require_alpha(text: str, what: str) -> None:
    if not text or any(not ("A" <= ch <= "Z") for ch in text):
        raise ValueError(f"{what} must be a non-empty string of letters A-Z only")


def validate_keys(vigenere_key: str, rails: int) -> None:
    _require_alpha(vigenere_key, "Vigenere key")
    if len(vigenere_key) < MIN_KEY_LEN:
        raise ValueError(f"Vigenere key must have at least {MIN_KEY_LEN} letters")
    if not isinstance(rails, int) or rails < 2:
        raise ValueError("Rail Fence depth must be an integer >= 2")


# ------------------------------------------------------------ Shift cipher
def shift_encrypt(plaintext: str, k: int) -> str:
    return "".join(chr((ord(c) - 65 + k) % 26 + 65) for c in plaintext)


def shift_decrypt(ciphertext: str, k: int) -> str:
    return shift_encrypt(ciphertext, -k)


# --------------------------------------------------------------- Vigenere
def vigenere_encrypt(plaintext: str, key: str) -> str:
    k = [ord(c) - 65 for c in key]
    L = len(k)
    return "".join(chr((ord(c) - 65 + k[i % L]) % 26 + 65)
                   for i, c in enumerate(plaintext))


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    k = [ord(c) - 65 for c in key]
    L = len(k)
    return "".join(chr((ord(c) - 65 - k[i % L]) % 26 + 65)
                   for i, c in enumerate(ciphertext))


# -------------------------------------------------------------- Rail Fence
def rail_fence_order(n: int, rails: int) -> List[int]:
    """Read-off order of the zig-zag: ciphertext[j] = text[order[j]].
    Rail 0 is read first, then rail 1, ... (top to bottom). O(n)."""
    if rails < 2 or rails >= n:
        return list(range(n))            # degenerate: identity permutation
    cycle = 2 * (rails - 1)
    order: List[int] = []
    for r in range(rails):
        for start in range(0, n, cycle):
            i = start + r
            if i < n:
                order.append(i)
            if 0 < r < rails - 1:
                j = start + cycle - r
                if j < n:
                    order.append(j)
    return order


def rail_fence_encrypt(text: str, rails: int) -> str:
    order = rail_fence_order(len(text), rails)
    return "".join(text[i] for i in order)


def rail_fence_decrypt(text: str, rails: int) -> str:
    order = rail_fence_order(len(text), rails)
    out = [""] * len(text)
    for j, i in enumerate(order):
        out[i] = text[j]
    return "".join(out)


# ------------------------------------------------------------ custom cipher
def encrypt(plaintext: str, vigenere_key: str, rails: int) -> str:
    """Stage 1 (Vigenere) then Stage 2 (Rail Fence)."""
    validate_keys(vigenere_key, rails)
    _require_alpha(plaintext, "Plaintext")
    return rail_fence_encrypt(vigenere_encrypt(plaintext, vigenere_key), rails)


def decrypt(ciphertext: str, vigenere_key: str, rails: int) -> str:
    """Undo Stage 2 (Rail Fence) then Stage 1 (Vigenere)."""
    validate_keys(vigenere_key, rails)
    _require_alpha(ciphertext, "Ciphertext")
    return vigenere_decrypt(rail_fence_decrypt(ciphertext, rails), vigenere_key)
