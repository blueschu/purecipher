use std::u8;

/// Trait for pure (stateless) ciphers.
///
/// Implementors are expected to implement `PureCipher::encipher` and
/// `PureCipher::decipher` as inverses of one another. This invariant, however,
/// was not deemed strong enough to merit marking this trait as unsafe.
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