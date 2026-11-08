"""Crops the CrypTool screenshots and assembles them into labelled report figures."""
import os, glob
from PIL import Image, ImageDraw, ImageFont

SRC = sorted(glob.glob("/mnt/user-data/uploads/Screenshot_2026-11-08_*.png"))
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "screenshots")
os.makedirs(OUT, exist_ok=True)
FONT = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 17)
BORDER = (150, 150, 150)

def crop(i, box):
    return Image.open(SRC[i - 1]).convert("RGB").crop(box)

def labelled(img, text, width=None):
    if width and img.width != width:
        img = img.resize((width, round(img.height * width / img.width)), Image.LANCZOS)
    bar = 30
    out = Image.new("RGB", (img.width + 2, img.height + bar + 2), "white")
    d = ImageDraw.Draw(out)
    d.rectangle([0, 0, out.width - 1, out.height - 1], outline=BORDER)
    d.text((8, 5), text, fill=(20, 40, 90), font=FONT)
    out.paste(img, (1, bar + 1))
    return out

def stack(panels, gap=14):
    W = max(p.width for p in panels); H = sum(p.height for p in panels) + gap * (len(panels) - 1)
    out = Image.new("RGB", (W, H), "white"); y = 0
    for p in panels:
        out.paste(p, (0, y)); y += p.height + gap
    return out

def grid(panels, cols=2, gap=14):
    rows = [panels[i:i + cols] for i in range(0, len(panels), cols)]
    rh = [max(p.height for p in r) for r in rows]
    W = max(sum(p.width for p in r) + gap * (len(r) - 1) for r in rows)
    out = Image.new("RGB", (W, sum(rh) + gap * (len(rows) - 1)), "white"); y = 0
    for r, h in zip(rows, rh):
        x = 0
        for p in r:
            out.paste(p, (x, y)); x += p.width + gap
        y += h + gap
    return out

# Figure 1 - workflow
fig1 = stack([
    labelled(crop(1, (236, 312, 1190, 366)), "(a) Plaintext: 'THE QUICK BROWN FOX ...' x3 (105 letters)"),
    labelled(crop(2, (262, 338, 1215, 392)), "(b) Stage 1: Vigenere encryption, key NETWORKSECURITY"),
    labelled(crop(3, (316, 388, 1270, 442)), "(c) Stage 2: Rail Fence encryption (Simple Transposition), key 3, offset 0"),
    labelled(crop(4, (90, 166, 1050, 220)), "(d) Decryption: Vigenere decryption of the Rail-Fence-decrypted text recovers the plaintext"),
])
fig1.save(f"{OUT}/fig1_workflow.png")

# Figure 2 - monogram histogram + frequency table
labelled(crop(10, (158, 232, 1735, 945)), "ASCII histogram of the Stage-1 ciphertext (105 characters)", width=1000).save(f"{OUT}/fig2_histogram.png")

# Figure 3 - digram / trigram / 4-gram
fig3 = grid([
    labelled(crop(11, (679, 350, 1243, 800)), "(a) Single letters (26 distinct)"),
    labelled(crop(12, (679, 350, 1243, 800)), "(b) Digrams (89 distinct)"),
    labelled(crop(13, (679, 350, 1243, 800)), "(c) Trigrams (100 distinct)"),
    labelled(crop(14, (679, 350, 1243, 800)), "(d) 4-grams (102 distinct)"),
], cols=2)
fig3.save(f"{OUT}/fig3_ngrams.png")

# Figure 4 - entropy + periodicity
fig4 = grid([
    labelled(crop(9, (802, 488, 1118, 662)), "(a) Entropy"),
    labelled(crop(7, (857, 520, 1062, 668)), "(b) Periodicity"),
], cols=2)
fig4.save(f"{OUT}/fig4_entropy_periodicity.png")

# Figure 5 - autocorrelation
labelled(crop(8, (133, 205, 1710, 922)), "Autocorrelation of the Stage-1 ciphertext", width=1000).save(f"{OUT}/fig5_autocorrelation.png")

# Figure 6 - floating frequency
fig6 = stack([
    labelled(crop(6, (107, 180, 1683, 896)), "(a) Floating frequency of the Stage-1 (Vigenere) ciphertext", width=950),
    labelled(crop(5, (81, 152, 1658, 868)), "(b) Floating frequency of the final (Rail Fence) ciphertext", width=950),
])
fig6.save(f"{OUT}/fig6_floating_frequency.png")
for f in sorted(os.listdir(OUT)):
    print(f, Image.open(f"{OUT}/{f}").size)
