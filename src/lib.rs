//! A crate implementing pure (stateless) ciphers.

pub mod ciphers;
pub mod classic;

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
/// let cipher = purecipher::classic::caesar();
/// let text = "The invasion will take place at dawn.".to_owned();
///
/// let ciphered_bytes = purecipher::encipher_bytes(&cipher, &text);
///
/// assert_eq!(
///     "Wkh lqydvlrq zloo wdnh sodfh dw gdzq.".as_bytes(),
///     &ciphered_bytes[..]
/// );
/// ```
pub fn encipher_bytes(cipher: &dyn PureCipher, bytes: impl AsRef<[u8]>) -> Vec<u8> {
    bytes.as_ref().iter().map(|&b| cipher.encipher(b)).collect()
}

/// Decipher some bytes with the given pure cipher.
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
/// let cipher = purecipher::classic::caesar();
/// let cipher_text = "Wkh lqydvlrq zloo wdnh sodfh dw gdzq.".to_owned();
///
/// let deciphered_bytes = purecipher::decipher_bytes(&cipher, &cipher_text);
///
/// assert_eq!(
///     "The invasion will take place at dawn.".as_bytes(),
///     &deciphered_bytes[..]
/// );
/// ```
pub fn decipher_bytes(cipher: &dyn PureCipher, bytes: impl AsRef<[u8]>) -> Vec<u8> {
    bytes.as_ref().iter().map(|&b| cipher.decipher(b)).collect()
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
