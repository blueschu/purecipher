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

    def test_encipher_str_matches_buffer(self):
        # Depends on SubstitutionBuilder being implemented correctly
        cipher = purecipher.SubstitutionBuilder() \
            .rotate(b'\x00', b'\xff', 1) \
            .into_cipher()
        buffer = bytearray(1)
        # Test all bytes in [1,126]. NULL adn bytes >=0x7f cannot be tested
        # because Python strings must be valid utf-8 with no embedded NULLs.
        for i in range(1, 127):
            buffer[0] = i
            buffer_s = buffer.decode('utf-8')
            cipher.encipher_buffer(buffer)
            self.assertEqual(cipher.encipher(buffer_s), buffer.decode())



class BuilderTest(unittest.TestCase):

    def test_builder_new_matches_null(self):
        ciphers = (
            purecipher.SubstitutionBuilder().into_cipher(),
            purecipher.Cipher(),
        )
        for b in range(0, 256):
            s = str(b)
            for cipher in ciphers:
                self.assertEqual(s, cipher.encipher(s))

    def test_builder_rotate(self):
        # Check all offsets in [-255,255]
        for offset in range(-255, 256):
            cipher = (
                purecipher.SubstitutionBuilder()
                    .rotate(b'\x00', b'\xff', offset)
                    .into_cipher()
            )
            buffer = bytearray(1)
            for i in range(0, 256):
                buffer[0] = i
                cipher.encipher_buffer(buffer)
                self.assertEqual(((i + offset) % 256), buffer[0])
                cipher.decipher_buffer(buffer)
                self.assertEqual(i, buffer[0])

    def test_builder_swap(self):
        cipher = (
            purecipher.SubstitutionBuilder()
                .swap(b'a', b'b')  # a->b, b->a
                .swap(b'b', b'c')  # c->a, b->c, a->b
                .swap(b'd', b'e')  # c->a, b->c, a->b, d->e, e->d
                .swap(b'd', b'c')  # d->a, c->e, b->c, a->b, e->d
                .into_cipher()
        )
        self.assertEqual('bcead', cipher.encipher('abcde'))

    def test_builder_raises_error_when_consumed(self):
        builder = purecipher.SubstitutionBuilder()
        builder.into_cipher()  # return ignored

        with self.assertRaises(purecipher.BuilderError):
            builder.rotate(b'\x00', b'\xff', 1)
        with self.assertRaises(purecipher.BuilderError):
            builder.swap(b'a', b'b')

    def test_is_consumed(self):
        builder = purecipher.SubstitutionBuilder()
        self.assertFalse(builder.is_consumed())
        builder.into_cipher()  # return ignored
        self.assertTrue(builder.is_consumed())
