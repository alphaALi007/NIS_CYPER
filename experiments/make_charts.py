"""Draws the report's result charts from results/results.json and results/benchmark.json."""
import os, json, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from attacks.langmodel import ENGLISH_FREQ

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R = json.load(open(f"{ROOT}/results/results.json"))
B = json.load(open(f"{ROOT}/results/benchmark.json"))
OUT = f"{ROOT}/docs/screenshots"
NAVY, ORANGE, GREEN, GREY, RED = "#1f3b73", "#e07b00", "#2a8f5b", "#8a8f98", "#b3261e"
plt.rcParams.update({"font.size": 11, "axes.spines.top": False, "axes.spines.right": False,
                     "axes.grid": True, "grid.alpha": 0.25, "axes.titleweight": "bold"})
L = [chr(65 + i) for i in range(26)]

# ---- Figure 7: letter frequencies -------------------------------------
fig, ax = plt.subplots(1, 2, figsize=(12, 4.2), sharey=True)
ax[0].bar(L, R["E4_freqs"]["plain"], color=NAVY, label="Plaintext sample (5,000 letters)")
ax[0].plot(L, ENGLISH_FREQ * 100, "o", color=ORANGE, ms=4, label="Standard English frequency")
ax[0].set_title("(a) Plaintext: peaks at E, T, A, O, N")
ax[1].bar(L, R["E4_freqs"]["stage1"], color=GREEN, label="Ciphertext (Vigenere + Rail Fence)")
ax[1].plot(L, ENGLISH_FREQ * 100, "o", color=ORANGE, ms=4, label="Standard English frequency")
ax[1].set_title("(b) Ciphertext: flattened, no dominant letter")
for a in ax:
    a.set_xlabel("Letter"); a.legend(frameon=False, loc="upper right")
ax[0].set_ylabel("Relative frequency (%)")
plt.tight_layout(); plt.savefig(f"{OUT}/fig7_letter_frequencies.png", dpi=110); plt.close()

# ---- Figure 8: attack results -------------------------------------------
e1, e2, e2b = R["E1_ciphertext_only"], R["E2a_known_plaintext_vs_m"], R["E2b_known_plaintext_vs_n"]
fig, ax = plt.subplots(2, 2, figsize=(12, 8.4))
a = ax[0, 0]
x = [d["n"] for d in e1]
a.plot(range(len(x)), [d["success"] * 100 for d in e1], "o-", color=NAVY, lw=2, label="Exact full-message recovery")
a.plot(range(len(x)), [d["mean_acc"] * 100 for d in e1], "s--", color=ORANGE, lw=1.5, label="Mean letters recovered")
a.set_xticks(range(len(x))); a.set_xticklabels(x); a.set_ylim(-3, 105)
a.set_xlabel("Ciphertext length n (letters)"); a.set_ylabel("%")
a.set_title("(a) Ciphertext-only (frequency) attack"); a.legend(frameon=False, loc="lower right")
a = ax[0, 1]
a.plot([d["m"] for d in e2], [d["success"] * 100 for d in e2], "o-", color=GREEN, lw=2)
a.axvline(14, color=RED, ls=":", lw=1.5); a.text(14.8, 45, "m = key length (14)", color=RED, fontsize=10)
a.set_xlabel("Known plaintext prefix length m (letters)"); a.set_ylabel("Success rate (%)")
a.set_ylim(-3, 105); a.set_title("(b) Known-plaintext attack (n = 500)")
a = ax[1, 0]
a.plot(range(len(x)), [d["mean_s"] * 1000 for d in e1], "o-", color=NAVY, lw=2, label="Ciphertext-only")
xb = [d["n"] for d in e2b]
a.plot([x.index(v) if v in x else np.nan for v in xb], [d["mean_s"] * 1000 for d in e2b], "s-", color=GREEN, lw=2, label="Known-plaintext (m = 20)")
a.set_xticks(range(len(x))); a.set_xticklabels(x); a.set_yscale("log")
a.set_xlabel("Ciphertext length n (letters)"); a.set_ylabel("Mean attack time (ms, log scale)")
a.set_title("(c) Computational effort: wall-clock"); a.legend(frameon=False)
a = ax[1, 1]
coa_h = np.mean([d["mean_hyp"] for d in e1]); kpa_h = [d for d in e2 if d["m"] == 20][0]["mean_hyp"]
brute = float(26 ** 15) * 29
bars = ["Ciphertext-only\nattack", "Known-plaintext\nattack (m = 20)", "Exhaustive key search\n(26^15 x 29 depths)"]
vals = [coa_h, kpa_h, brute]
b = a.bar(bars, vals, color=[NAVY, GREEN, GREY]); a.set_yscale("log"); a.set_ylim(1, 1e25)
for r, v in zip(b, vals):
    a.text(r.get_x() + r.get_width() / 2, v * 2, f"{v:.1e}", ha="center", fontsize=10)
a.set_ylabel("Key hypotheses evaluated (log scale)"); a.set_title("(d) Computational effort: hypotheses tested")
plt.tight_layout(); plt.savefig(f"{OUT}/fig8_attack_results.png", dpi=110); plt.close()

# ---- Figure 9: performance ------------------------------------------------
fig, ax = plt.subplots(1, 2, figsize=(12, 4.4))
n = [r["n"] for r in B]
for key, lab, col, mk in [("shift_enc", "Shift encrypt", GREY, "s"), ("custom_enc", "Custom encrypt", NAVY, "o"),
                          ("custom_dec", "Custom decrypt", ORANGE, "^")]:
    ax[0].plot(n, [r[key] * 1000 for r in B], mk + "-", color=col, lw=2, label=lab)
    ax[1].plot(n, [r[key] / r["n"] * 1e9 for r in B], mk + "-", color=col, lw=2, label=lab)
ax[0].set_xscale("log"); ax[0].set_yscale("log")
ax[0].set_xlabel("Message length n (letters)"); ax[0].set_ylabel("Time (ms)")
ax[0].set_title("(a) Run time grows linearly: O(n)"); ax[0].legend(frameon=False)
ax[1].set_xscale("log"); ax[1].set_xlabel("Message length n (letters)"); ax[1].set_ylabel("Time per letter (ns)")
ax[1].set_ylim(0, 260); ax[1].set_title("(b) Cost per letter is constant"); ax[1].legend(frameon=False)
plt.tight_layout(); plt.savefig(f"{OUT}/fig9_performance.png", dpi=110); plt.close()
print("charts done")
