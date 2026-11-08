#!/usr/bin/env python3
"""Command-line front end for the CT-486 CCP cipher.

  python main.py encrypt "Meet me at noon" --key NETWORKSECURITY --rails 3
  python main.py decrypt GIFVN... --key NETWORKSECURITY --rails 3
  python main.py break-ciphertext-only CIPHERTEXT
  python main.py break-known-plaintext CIPHERTEXT --known HELLOWORLD
  python main.py demo
"""
import argparse
from cipher import encrypt, decrypt, normalize
from attacks.langmodel import split_corpus, QuadgramModel
from attacks.ciphertext_only import ciphertext_only_attack
from attacks.known_plaintext import known_plaintext_attack


def model():
    return QuadgramModel(split_corpus()[0])


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest="cmd", required=True)
    for name in ("encrypt", "decrypt"):
        p = sp.add_parser(name); p.add_argument("text")
        p.add_argument("--key", required=True, help="Vigenere key, >= 10 letters A-Z")
        p.add_argument("--rails", type=int, default=3, help="Rail Fence depth (>= 2)")
    p = sp.add_parser("break-ciphertext-only"); p.add_argument("ciphertext")
    p.add_argument("--max-rails", type=int, default=30); p.add_argument("--max-key", type=int, default=30)
    p = sp.add_parser("break-known-plaintext"); p.add_argument("ciphertext")
    p.add_argument("--known", required=True, help="known plaintext prefix")
    sp.add_parser("demo")
    a = ap.parse_args()

    if a.cmd == "encrypt":
        print(encrypt(normalize(a.text), normalize(a.key), a.rails))
    elif a.cmd == "decrypt":
        print(decrypt(normalize(a.text), normalize(a.key), a.rails))
    elif a.cmd == "break-ciphertext-only":
        r = ciphertext_only_attack(normalize(a.ciphertext), model(), a.max_rails, a.max_key)
        print(f"rails={r['rails']} key={r['key']} time={r['seconds']:.3f}s\n{r['plaintext']}")
    elif a.cmd == "break-known-plaintext":
        r = known_plaintext_attack(normalize(a.ciphertext), normalize(a.known), model())
        print(f"rails={r['rails']} key={r['key']} time={r['seconds']:.4f}s\n{r['plaintext']}")
    else:
        pt = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG" * 3
        ct = encrypt(pt, "NETWORKSECURITY", 3)
        print("plaintext :", pt); print("ciphertext:", ct)
        print("decrypted :", decrypt(ct, "NETWORKSECURITY", 3) == pt)
        r = known_plaintext_attack(ct, pt[:15], model())
        print("known-plaintext attack (15 known letters): rails=%s key=%s success=%s"
              % (r["rails"], r["key"], r["plaintext"] == pt))


if __name__ == "__main__":
    main()
