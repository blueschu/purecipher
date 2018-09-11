//! A crate implementing pure (stateless) ciphers.
//!
//! The API provided by this crate is intentionally limited in scope. Structures
//! and methods are included only to simplify the logic within the crate or to
//! provide an interesting api to expose over the foreign function interface.

mod substitution;
mod classic;

pub use self::substitution::{SubstitutionCipher, SubstitutionBuilder};
pub use self::classic::{caesar, leet_speak, rot13_alpha};

use std::u8;

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
/// let cipher = purecipher::caesar();
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
/// let cipher = purecipher::caesar();
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

/// Trait for pure (stateless) ciphers.
///
/// Implementors are expected to implement `PureCipher::encipher` and
/// `PureCipher::decipher` as inverses of one another. This invariant, however,
/// was not deemed strong enough to merit marking this trait as unsafe.
///
/// This trait is largely unnecessaryf or the functionality of this crate: all
/// "pure" ciphers can be expressed as a trivial substitution cipher. This trait
/// exists only to enable the demonstration of passing trait objects over FFI
/// boundaries.
///
/// # Example
/// ```
/// use std::u8;
///
/// use purecipher::PureCipher;
///
/// struct ShiftOne;
///
/// impl PureCipher for ShiftOne {
///     fn encipher(&self, token: u8) -> u8 {
///         if token == u8::MAX { 0 } else { token + 1 }
///     }
///
///     fn decipher(&self, token: u8) -> u8 {
///         if token == 0 { u8::MAX } else { token - 1 }
///     }
/// }
///
/// let cipher = ShiftOne;
/// assert_eq!(b'B', cipher.encipher(b'A'));
/// assert_eq!(b'A', cipher.decipher(b'B'));
/// ```
pub trait PureCipher {
    /// Enciphers a single byte.
    fn encipher(&self, token: u8) -> u8;

    /// Deciphers a single bytes.
    fn decipher(&self, token: u8) -> u8;

    /// Enciphers a buffer of bytes inplace.
    fn encipher_inplace(&self, bytes: &mut [u8]) {
        for b in bytes.iter_mut() {
            *b = self.encipher(*b);
        }
    }

    /// Deciphers a buffer of bytes inplace.
    fn decipher_inplace(&self, bytes: &mut [u8]) {
        for b in bytes.iter_mut() {
            *b = self.decipher(*b);
        }
    }
}

/// Cipher that performs no ciphering.
///
/// Enciphering and deciphering bytes with this cipher are no-ops. Each of
/// these operations result in the same byte being returned.
///
/// This cipher captures all of the security benefits that are provided by the
/// ciphers in this crate while removing all layers of unnecessary obscurity.
pub struct NullCipher;

impl PureCipher for NullCipher {
    fn encipher(&self, token: u8) -> u8 { token }

    fn decipher(&self, token: u8) -> u8 { token }
}

impl Into<Box<dyn PureCipher>> for Option<Box<dyn PureCipher>> {
    fn into(self) -> Box<PureCipher> {
        self.unwrap_or(Box::new(NullCipher {}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encipher_str_bytes() {
        use super::NullCipher;

        let text = "this is a test";

        let cipher_text = encipher_bytes(&NullCipher {}, &text);

        assert_eq!(cipher_text, text.as_bytes());
    }
}
