//! A crate implementing pure (stateless) ciphers.

pub mod ciphers;

pub use self::ciphers::PureCipher;

/// Encipher some bytes with the given pure cipher.
///
/// This function accepts data in the form of any type that implements
/// `AsRef<[u8]>`, so it can operate on most standard types that abstract
/// over a collection of bytes.
///
/// Since it cannot be guaranteed that user provided ciphers will produce
/// valid unicode, the ciphered data is returned as a `Vec<u8>`. If a
/// `String` is desired, you must perform the conversion yourself.
/// See `String::from_utf8`.
///
/// # Example
/// ```
/// let cipher = purecipher::ciphers::NullCipher;
/// let text = "The invasion will take place at dawn.".to_owned();
///
/// let ciphered_bytes = purecipher::encipher_bytes(&cipher, &text);
///
/// assert_eq!(text.as_bytes(), &ciphered_bytes[..]);
///
/// let ciphered_str = String::from_utf8(ciphered_bytes).unwrap();
/// assert_eq!(text, ciphered_str);
/// ```
pub fn encipher_bytes(cipher: &dyn PureCipher, bytes: impl AsRef<[u8]>) -> Vec<u8> {
    bytes.as_ref().iter().map(|&b| cipher.encipher(b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encipher_str_bytes() {
        use super::ciphers::NullCipher;

        let text = "this is a test";

        let cipher_text = encipher_bytes(&NullCipher {}, &text);

        assert_eq!(cipher_text, text.as_bytes());
    }
}
