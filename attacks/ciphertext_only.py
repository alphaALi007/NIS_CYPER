"""
Ciphertext-only attack (frequency analysis).

The Rail Fence stage has only n-2 possible keys, so the attacker simply tries
every plausible depth, strips that stage, and is left with a plain Vigenere
cryptogram that falls to classical statistics:

  1. for every rail depth d   : undo Rail Fence -> candidate Stage-1 text V_d
  2. key length               : mean Index of Coincidence (IC) of the columns of V_d
  3. each key letter          : chi-squared test against English letter frequencies
  4. polish + ranking         : quadgram fitness, coordinate ascent on the key
"""
import time
import numpy as np
from .langmodel import ENGLISH_FREQ, index_of_coincidence, to_array, to_text, QuadgramModel
from .common import rail_inverse, vig_decrypt


def mean_ic(v: np.ndarray, L: int) -> float:
    tot = 0.0
    for j in range(L):
        tot += index_of_coincidence(v[j::L])
    return tot / L


def chi_key(v: np.ndarray, L: int) -> np.ndarray:
    key = np.zeros(L, dtype=np.int64)
    for j in range(L):
        col = v[j::L]
        cnt = np.bincount(col, minlength=26).astype(float)
        m = max(len(col), 1)
        best, best_s = None, 0
        for s in range(26):
            obs = np.roll(cnt, -s)                      # decrypting with shift s
            chi = (((obs - m * ENGLISH_FREQ) ** 2) / (m * ENGLISH_FREQ)).sum()
            if best is None or chi < best:
                best, best_s = chi, s
        key[j] = best_s
    return key


def polish(v, key, model, passes=2):
    key = key.copy()
    cur = model.score(vig_decrypt(v, key))
    for _ in range(passes):
        improved = False
        for j in range(len(key)):
            orig = key[j]
            for s in range(26):
                if s == orig:
                    continue
                key[j] = s
                sc = model.score(vig_decrypt(v, key))
                if sc > cur + 1e-9:
                    cur, orig, improved = sc, s, True
            key[j] = orig
        if not improved:
            break
    return key, cur


def ciphertext_only_attack(ciphertext: str, model: QuadgramModel,
                           max_rails=30, max_key=30, top_depths=3, top_lengths=3):
    """Returns dict(plaintext, rails, key, score, hypotheses, seconds)."""
    t0 = time.perf_counter()
    c = to_array(ciphertext)
    n = len(c)
    hyp = 0
    ranked = []
    for d in range(2, min(max_rails, n - 1) + 1):
        v = rail_inverse(c, d)
        ics = [(mean_ic(v, L), L) for L in range(1, min(max_key, n // 2) + 1)]
        hyp += len(ics)
        ics.sort(reverse=True)
        ranked.append((ics[0][0], d, v, [L for _, L in ics[:top_lengths]]))
    ranked.sort(key=lambda t: -t[0])

    best = None
    for _, d, v, Ls in ranked[:top_depths]:
        for L in Ls:
            key = chi_key(v, L)
            hyp += 26 * L
            sc = model.score(vig_decrypt(v, key))
            if best is None or sc > best[0]:
                best = (sc, d, v, key)
    sc, d, v, key = best
    key, sc = polish(v, key, model)
    hyp += 2 * 26 * len(key)
    pt = to_text(vig_decrypt(v, key))
    return dict(plaintext=pt, rails=d, key=to_text(key), score=sc,
                hypotheses=hyp, seconds=time.perf_counter() - t0)
