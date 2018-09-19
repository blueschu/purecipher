import unittest

import purecipher


class CipherTest(unittest.TestCase):

    def test_cipher_caesar(self):
        cipher = purecipher.caesar()
        message = 'We attack at dawn.'
        cipher_text = cipher.encipher(message)
        self.assertEqual('Zh dwwdfn dw gdzq.', cipher_text)
        self.assertEqual(message, cipher.decipher(cipher_text))

    def test_cipher_rot13(self):
        cipher = purecipher.rot13()

        message = 'Lovely plumage, the Norwegian Blue.'
        cipher_text = cipher.encipher(message)
        self.assertEqual('Ybiryl cyhzntr, gur Abejrtvna Oyhr.', cipher_text)
        self.assertEqual(message, cipher.decipher(cipher_text))

    def test_cipher_leet(self):
        cipher = purecipher.leet()

        message = 'Pure ciphers are the BEST!'
        cipher_text = cipher.encipher(message)
        self.assertEqual('Pur3 c!ph3rs @r3 1h3 BE5Ti', cipher_text)
        self.assertEqual(message, cipher.decipher(cipher_text))
