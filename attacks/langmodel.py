"""English language statistics used by the attacker (numpy)."""
import re
import numpy as np

# Standard English letter frequencies (percent), Lewand 2000.
ENGLISH_FREQ = np.array([
    8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153,
    0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056,
    2.758, 0.978, 2.360, 0.150, 1.974, 0.074]) / 100.0


def to_array(text: str) -> np.ndarray:
    return np.frombuffer(text.encode("ascii"), dtype=np.uint8).astype(np.int64) - 65


def to_text(arr) -> str:
    return (np.asarray(arr, dtype=np.int64) % 26 + 65).astype(np.uint8).tobytes().decode("ascii")


def index_of_coincidence(arr: np.ndarray) -> float:
    m = len(arr)
    if m < 2:
        return 0.0
    cnt = np.bincount(arr, minlength=26)
    return float((cnt * (cnt - 1)).sum() / (m * (m - 1)))


def entropy(arr: np.ndarray) -> float:
    cnt = np.bincount(arr, minlength=26).astype(float)
    p = cnt[cnt > 0] / cnt.sum()
    return float(-(p * np.log2(p)).sum())


def load_corpus() -> str:
    """English-like reference corpus that ships with every Python install
    (the pydoc help topics, ~330k letters). The first 70 % trains the attacker's
    model; the last 30 % is used only to draw test plaintexts, so training data
    and test data never overlap."""
    import pydoc_data.topics as T
    raw = "\n".join(T.topics[k] for k in sorted(T.topics))
    return re.sub(r"[^A-Z]", "", raw.upper())


def split_corpus():
    c = load_corpus()
    cut = int(len(c) * 0.7)
    return c[:cut], c[cut:]


class QuadgramModel:
    """Log10-probability table for all 26^4 letter quadruples."""

    def __init__(self, training_text: str):
        a = to_array(training_text)
        idx = a[:-3] * 17576 + a[1:-2] * 676 + a[2:-1] * 26 + a[3:]
        cnt = np.bincount(idx, minlength=26 ** 4).astype(float)
        total = cnt.sum()
        floor = np.log10(0.01 / total)
        with np.errstate(divide="ignore"):
            self.table = np.where(cnt > 0, np.log10(np.maximum(cnt, 1) / total), floor)

    def score(self, arr: np.ndarray) -> float:
        """Mean log10 probability per quadgram (higher = more English-like)."""
        if len(arr) < 4:
            return -10.0
        idx = arr[:-3] * 17576 + arr[1:-2] * 676 + arr[2:-1] * 26 + arr[3:]
        return float(self.table[idx].mean())
