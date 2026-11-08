# CT-486 CCP - Design and Break a Custom Classical Cipher

Two-stage cipher: **Stage 1 Vigenere** (key >= 10 letters) -> **Stage 2 Rail Fence** (depth >= 2),
plus two attacks (ciphertext-only frequency analysis, known-plaintext) and a benchmark suite.

    C = RailFence_d( Vigenere_K(P) )          P = Vigenere_K^-1( RailFence_d^-1(C) )

## Layout
| Path | Purpose |
|---|---|
| `cipher/classical.py` | Shift, Vigenere, Rail Fence and the custom cipher (`encrypt`, `decrypt`) |
| `attacks/ciphertext_only.py` | Rail-depth sweep + Index of Coincidence + chi-squared + quadgram polish |
| `attacks/known_plaintext.py` | Keystream recovery from a known plaintext prefix |
| `attacks/langmodel.py` | English statistics (letter table, IC, entropy, quadgram model) |
| `experiments/run_experiments.py` | Success-rate / effort experiments (seeded, reproducible) -> `results/results.json` |
| `experiments/benchmark.py` | Encrypt/decrypt timing vs Shift cipher -> `results/benchmark.json` |
| `experiments/make_charts.py`, `make_screenshot_figures.py` | Report figures |
| `tests/test_cipher.py` | Unit tests, including the exact CrypTool 1.4.42 ciphertexts |
| `main.py` | Command-line interface |

## Run
    pip install -r requirements.txt
    python tests/test_cipher.py              # 8 tests
    python main.py demo
    python main.py encrypt "Attack at dawn" --key NETWORKSECURITY --rails 3
    python experiments/run_experiments.py    # ~2 minutes
    python experiments/benchmark.py

Only letters A-Z are encrypted; `main.py` upper-cases input and drops spaces and punctuation.
The attacker's English model is trained on the first 70 % of the pydoc help text bundled with Python;
test plaintexts come from the last 30 %, so training and test data never overlap.
