"""Timing of the Shift cipher vs the custom two-stage cipher (pure Python, O(n) each)."""
import sys, os, json, time, random, statistics as st
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cipher import (ALPHABET, shift_encrypt, shift_decrypt, vigenere_encrypt, vigenere_decrypt,
                    rail_fence_encrypt, rail_fence_decrypt, encrypt, decrypt)

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")
rnd = random.Random(7)
KEY, RAILS = "NETWORKSECURITY", 3


def med(fn, repeat):
    ts = []
    for _ in range(repeat):
        t = time.perf_counter(); fn(); ts.append(time.perf_counter() - t)
    return st.median(ts)


rows = []
for n in (1_000, 10_000, 100_000, 1_000_000):
    pt = "".join(rnd.choice(ALPHABET) for _ in range(n))
    rep = 15 if n <= 100_000 else 5
    ct_shift, ct_vig = shift_encrypt(pt, 3), vigenere_encrypt(pt, KEY)
    ct_custom = encrypt(pt, KEY, RAILS)
    assert decrypt(ct_custom, KEY, RAILS) == pt
    rows.append(dict(
        n=n,
        shift_enc=med(lambda: shift_encrypt(pt, 3), rep),
        shift_dec=med(lambda: shift_decrypt(ct_shift, 3), rep),
        vig_enc=med(lambda: vigenere_encrypt(pt, KEY), rep),
        rail_enc=med(lambda: rail_fence_encrypt(pt, RAILS), rep),
        custom_enc=med(lambda: encrypt(pt, KEY, RAILS), rep),
        custom_dec=med(lambda: decrypt(ct_custom, KEY, RAILS), rep),
    ))
    print({k: (round(v * 1000, 3) if k != "n" else v) for k, v in rows[-1].items()}, "ms", flush=True)
json.dump(rows, open(os.path.join(OUT, "benchmark.json"), "w"), indent=1)
