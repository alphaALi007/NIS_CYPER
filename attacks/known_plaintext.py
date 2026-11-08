"""
Known-plaintext attack.

Assumption: the attacker holds the full ciphertext C and knows the first m
letters of the plaintext (e.g. a standard greeting / header) -- the
'portion of the plaintext' of the assignment.

  for every rail depth d:
      V = RailFence_d^-1(C)                 (candidate Stage-1 text)
      keystream[i] = V[i] - P[i]  (mod 26)  for the m known positions
      for every key length L:  keep L if keystream has period L
                               (then key = keystream[:L])
      decrypt the *whole* V with the key and rank by English fitness
The wrong depths give a random keystream, the right depth gives a periodic one.
"""
import time
import numpy as np
from .langmodel import to_array, to_text, QuadgramModel
from .common import rail_inverse, vig_decrypt


def known_plaintext_attack(ciphertext: str, known_prefix: str, model: QuadgramModel,
                           max_rails=30, max_key=40):
    t0 = time.perf_counter()
    c, p = to_array(ciphertext), to_array(known_prefix)
    n, m = len(c), len(p)
    best, hyp = None, 0
    for d in range(2, min(max_rails, n - 1) + 1):
        v = rail_inverse(c, d)
        ks = (v[:m] - p) % 26
        for L in range(1, min(max_key, m) + 1):
            hyp += 1
            if L < m and not np.array_equal(ks[L:], ks[:m - L]):
                continue                                  # keystream not periodic with L
            key = ks[:L]
            cand = vig_decrypt(v, key)
            sc = model.score(cand)
            if best is None or sc > best[0]:
                best = (sc, d, key.copy(), cand)
            break                                         # smallest consistent L wins
    if best is None:
        return dict(plaintext="", rails=None, key="", score=-99, hypotheses=hyp,
                    seconds=time.perf_counter() - t0)
    sc, d, key, cand = best
    return dict(plaintext=to_text(cand), rails=d, key=to_text(key), score=sc,
                hypotheses=hyp, seconds=time.perf_counter() - t0)
