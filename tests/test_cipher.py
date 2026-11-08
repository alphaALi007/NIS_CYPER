import random, unittest, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cipher import *

# Values read from the CrypTool 1.4.42 screenshots (Figures 1-4 of the report)
PT   = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG" * 3
KEY  = "NETWORKSECURITY"
STAGE1 = ("GLXMIZMCFTINVYMKNNIDJYNITNYMEYMCWKUKRWUWCTSUPBAGBCOTMQRMFDXPGLXHOQIVSINYMJSVGDXFFGFJQRACFNFSOAFKRWPCTPLHE")
FINAL  = ("GIFVNJTEWRCPBMFGOSMGFQFORTELMZCTNYKNDYINMYCKKWWTUBGCTQMDPLHQVIYJVDFGJRCNSAKWCPHXMIMINYMUUSAORXXINSXFAFFPL")

class T(unittest.TestCase):
    def test_crypttool_stage1(self):
        self.assertEqual(vigenere_encrypt(PT, KEY), STAGE1)
    def test_crypttool_final(self):
        self.assertEqual(encrypt(PT, KEY, 3), FINAL)
    def test_crypttool_decrypt(self):
        self.assertEqual(decrypt(FINAL, KEY, 3), PT)
    def test_roundtrip_random(self):
        rnd = random.Random(1)
        for _ in range(300):
            n = rnd.randint(1, 400)
            pt = "".join(rnd.choice(ALPHABET) for _ in range(n))
            key = "".join(rnd.choice(ALPHABET) for _ in range(rnd.randint(10, 20)))
            d = rnd.randint(2, 12)
            self.assertEqual(decrypt(encrypt(pt, key, d), key, d), pt)
    def test_rail_is_permutation(self):
        for n in range(1, 80):
            for d in range(2, 12):
                self.assertEqual(sorted(rail_fence_order(n, d)), list(range(n)))
    def test_short_key_rejected(self):
        with self.assertRaises(ValueError): encrypt("HELLO", "SHORT", 3)
    def test_normalize(self):
        self.assertEqual(normalize("Hello, World 42!"), "HELLOWORLD")
    def test_shift(self):
        self.assertEqual(shift_decrypt(shift_encrypt("ATTACK", 7), 7), "ATTACK")

if __name__ == "__main__":
    unittest.main(verbosity=2)
