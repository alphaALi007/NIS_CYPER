"""Reproduces every number in the report's attack and statistics sections."""
import sys, os, json, random, statistics as st
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import numpy as np
from cipher import encrypt, vigenere_encrypt, ALPHABET
from attacks.langmodel import (split_corpus, QuadgramModel, to_array, index_of_coincidence,
                               entropy)
from attacks.ciphertext_only import ciphertext_only_attack
from attacks.known_plaintext import known_plaintext_attack

SEED = 2026
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")
os.makedirs(OUT, exist_ok=True)

train, test = split_corpus()
model = QuadgramModel(train)
rnd = random.Random(SEED)

PT = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG" * 3
KEY = "NETWORKSECURITY"


def rkey(L):
    return "".join(rnd.choice(ALPHABET) for _ in range(L))


def window(n):
    s = rnd.randint(0, len(test) - n)
    return test[s:s + n]


def accuracy(a, b):
    return sum(x == y for x, y in zip(a, b)) / len(b)


res = {"seed": SEED, "train_letters": len(train), "test_letters": len(test)}

# ---- E1: ciphertext-only attack vs ciphertext length --------------------
TR = 100
e1 = []
for n in (50, 100, 150, 200, 300, 500, 1000, 2000, 5000):
    ok, acc, tt, hy = 0, [], [], []
    for _ in range(TR):
        pt, L, d = window(n), rnd.randint(10, 16), rnd.randint(2, 20)
        r = ciphertext_only_attack(encrypt(pt, rkey(L), d), model)
        ok += r["plaintext"] == pt
        acc.append(accuracy(r["plaintext"], pt)); tt.append(r["seconds"]); hy.append(r["hypotheses"])
    e1.append(dict(n=n, trials=TR, success=ok / TR, mean_acc=st.mean(acc),
                   mean_s=st.mean(tt), mean_hyp=st.mean(hy)))
    print("COA", e1[-1], flush=True)
res["E1_ciphertext_only"] = e1

# ---- E2a: known-plaintext attack vs length of known prefix (n=500, |K|=14)
TR2 = 200
e2 = []
for m in (5, 8, 10, 12, 14, 16, 20, 30, 50, 100):
    ok, tt, hy = 0, [], []
    for _ in range(TR2):
        pt, d = window(500), rnd.randint(2, 20)
        r = known_plaintext_attack(encrypt(pt, rkey(14), d), pt[:m], model)
        ok += r["plaintext"] == pt; tt.append(r["seconds"]); hy.append(r["hypotheses"])
    e2.append(dict(m=m, n=500, key_len=14, trials=TR2, success=ok / TR2,
                   mean_s=st.mean(tt), mean_hyp=st.mean(hy)))
    print("KPA-m", e2[-1], flush=True)
res["E2a_known_plaintext_vs_m"] = e2

# ---- E2b: known-plaintext attack vs ciphertext length (m=20, |K|=14)
e2b = []
for n in (30, 50, 100, 500, 1000, 5000):
    ok, tt = 0, []
    for _ in range(TR2):
        pt, d = window(n), rnd.randint(2, 20)
        r = known_plaintext_attack(encrypt(pt, rkey(14), d), pt[:20], model)
        ok += r["plaintext"] == pt; tt.append(r["seconds"])
    e2b.append(dict(n=n, m=20, trials=TR2, success=ok / TR2, mean_s=st.mean(tt)))
    print("KPA-n", e2b[-1], flush=True)
res["E2b_known_plaintext_vs_n"] = e2b

# ---- E3: the group's own CrypTool sample --------------------------------
final = encrypt(PT, KEY, 3)
r = ciphertext_only_attack(final, model)
case = {"ciphertext_only": dict(recovered=r["plaintext"], rails=r["rails"], key=r["key"],
                                exact=r["plaintext"] == PT, accuracy=accuracy(r["plaintext"], PT),
                                seconds=r["seconds"])}
for m in (10, 14, 15, 20, 35):
    r = known_plaintext_attack(final, PT[:m], model)
    case[f"known_plaintext_m{m}"] = dict(exact=r["plaintext"] == PT, rails=r["rails"], key=r["key"],
                                         accuracy=accuracy(r["plaintext"], PT) if r["plaintext"] else 0,
                                         seconds=r["seconds"])
res["E3_case_study"] = case
print("CASE", json.dumps(case, indent=1), flush=True)

# ---- E4: statistics of plaintext / stage 1 / final ----------------------
def stats(t):
    a = to_array(t)
    f = np.bincount(a, minlength=26) / len(a) * 100
    return dict(n=len(t), ic=index_of_coincidence(a), entropy=entropy(a),
                max_freq=float(f.max()), max_letter=chr(65 + int(f.argmax())),
                distinct=int((f > 0).sum()))
pt_long = window(5000); k_long = rkey(14)
s1_long = vigenere_encrypt(pt_long, k_long); fin_long = encrypt(pt_long, k_long, 3)
res["E4_stats"] = {
    "sample_plain": stats(PT), "sample_stage1": stats(vigenere_encrypt(PT, KEY)), "sample_final": stats(final),
    "long_plain": stats(pt_long), "long_stage1": stats(s1_long), "long_final": stats(fin_long),
}
# repeated n-grams in the sample (Kasiski evidence)
def repeats(t, k):
    pos = {}
    for i in range(len(t) - k + 1):
        pos.setdefault(t[i:i + k], []).append(i)
    return {g: p for g, p in pos.items() if len(p) > 1}
res["E4_repeats"] = {"stage1_trigrams": repeats(vigenere_encrypt(PT, KEY), 3),
                     "final_trigrams": repeats(final, 3)}
# letter frequencies for the figure
res["E4_freqs"] = {
    "plain": (np.bincount(to_array(pt_long), minlength=26) / 5000 * 100).tolist(),
    "stage1": (np.bincount(to_array(s1_long), minlength=26) / 5000 * 100).tolist(),
}
json.dump(res, open(os.path.join(OUT, "results.json"), "w"), indent=1)
print("saved")
