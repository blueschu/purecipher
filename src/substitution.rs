//! Substitution-based pure ciphers.

use std::u8;
use std::fmt;
use std::ops::{Index, IndexMut};

use super::{PureCipher, NullCipher};

/// The number of values that can be index by a single unsigned byte.
const ALL_U8: usize = u8::MAX as usize + 1;

#[derive(Clone)]
/// Index based mapping between bytes.
struct ByteMapping([u8; ALL_U8]);

impl fmt::Debug for ByteMapping {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let entries: Vec<_> = self.0.iter()
            .enumerate()
            .map(|(i, &b)| (i as u8, b))
            .filter(|(i, b)| i != b)
            .map(|(i, b)| format!("{} => {}", i as char, b as char))
            .collect();
        f.debug_tuple("ByteMapping").field(&entries).finish()
    }
}

impl Default for ByteMapping {
    // Builds an array of every 8-bit byte in ascending order.
    fn default() -> Self {
        let mut bytes = [0; ALL_U8];
        for b in 0..=u8::MAX {
            bytes[b as usize] = b;
        }
        ByteMapping(bytes)
    }
}

impl Index<u8> for ByteMapping {
    type Output = u8;

    fn index(&self, index: u8) -> &<Self as Index<u8>>::Output {
        &self.0[index as usize]
    }
}

impl IndexMut<u8> for ByteMapping {
    fn index_mut(&mut self, index: u8) -> &mut <Self as Index<u8>>::Output {
        &mut self.0[index as usize]
    }
}

#[derive(Debug)]
/// Convenience structure to help build substitution ciphers.
///
/// For simplicity, ciphers may only be expressed with swaps and shifts.
pub struct SubstitutionBuilder {
    /// Index based mapping between bytes.
    map: ByteMapping,
}

impl SubstitutionBuilder {
    /// Build a new `SubstitutionBuilder` with each byte mapped to itself.
    ///
    /// # Examples
    /// ```
    /// use std::u8;
    /// use purecipher::{PureCipher, SubstitutionBuilder};
    ///
    /// let mut builder = SubstitutionBuilder::new();
    ///
    /// let cipher = builder.into_cipher();
    ///
    /// for b in 0..u8::MAX {
    ///     assert_eq!(b, cipher.encipher(b));
    /// }
    /// ```
    pub fn new() -> Self {
        Self { map: ByteMapping::default() }
    }

    /// Swaps the mappings of `left` and `right` in the resulting cipher.
    ///
    /// # Examples
    /// ```
    /// use purecipher::{PureCipher, SubstitutionBuilder};
    ///
    /// let mut builder = SubstitutionBuilder::new();
    ///
    /// builder.swap(b'A', b'B'); // A->B, B->A
    /// builder.swap(b'A', b'D'); // A->D, B->A, D->B
    ///
    /// let cipher = builder.into_cipher();
    ///
    /// assert_eq!(b'D', cipher.encipher(b'A'));
    /// assert_eq!(b'A', cipher.encipher(b'B'));
    /// assert_eq!(b'C', cipher.encipher(b'C'));
    /// assert_eq!(b'B', cipher.encipher(b'D'));
    /// ```
    pub fn swap(&mut self, left: u8, right: u8) {
        let buf = self.map[left];
        self.map[left] = self.map[right];
        self.map[right] = buf;
    }

    /// Rotates the mapping target of each byte in the resulting cipher.
    ///
    /// # Panics
    /// This method will panic if `to` < `from`.
    ///
    /// # Examples
    /// ```
    /// use purecipher::{PureCipher, SubstitutionBuilder};
    ///
    /// let mut builder = SubstitutionBuilder::new();
    /// builder.rotate_range(b'A', b'C', 1);
    ///
    /// let cipher = builder.into_cipher();
    ///
    /// assert_eq!(b'B', cipher.encipher(b'A'));
    /// assert_eq!(b'C', cipher.encipher(b'B'));
    /// assert_eq!(b'A', cipher.encipher(b'C'));
    /// assert_eq!(b'D', cipher.encipher(b'D'));
    /// ```
    pub fn rotate_range(&mut self, from: u8, to: u8, offset: isize) {
        let abs_offset = offset.abs() as usize % (1 + to as u16 - from as u16) as usize;
        let slice = &mut self.map.0[from as usize..=to as usize];

        if offset < 0 {
            slice.rotate_right(abs_offset);
        } else {
            slice.rotate_left(abs_offset);
        }
    }

    /// Convert this builder into a substitution cipher.
    pub fn into_cipher(self) -> SubstitutionCipher { self.into() }
}

impl Into<SubstitutionCipher> for SubstitutionBuilder {
    fn into(self) -> SubstitutionCipher {
        SubstitutionCipher::from_bytes_unchecked(self.map)
    }
}

#[derive(Debug)]
/// Cipher that transforms bytes via direct substitution.
pub struct SubstitutionCipher {
    /// Index-based mapping to encipher bytes.
    map: ByteMapping,
    /// Index-based mapping to decipher bytes.
    inv: ByteMapping,
}

impl SubstitutionCipher {
    /// Build a `SubstitutionCipher` from the given byte mapping.
    ///
    /// Please note that duplicate bytes in the provided byte mapping will
    /// result in an irreversible cipher.
    fn from_bytes_unchecked(map: ByteMapping) -> Self {
        let mut inv = ByteMapping([0; ALL_U8]);
        for (i, &b) in map.0.iter().enumerate() {
            inv[b] = i as u8;
        }
        Self { map, inv }
    }
}

impl Default for SubstitutionCipher {
    fn default() -> Self {
        let map = ByteMapping::default();
        Self { inv: map.clone(), map }
    }
}

impl From<NullCipher> for SubstitutionCipher {
    fn from(_: NullCipher) -> Self {
        Self::default()
    }
}

impl PureCipher for SubstitutionCipher {
    fn encipher(&self, token: u8) -> u8 {
        self.map[token]
    }

    fn decipher(&self, token: u8) -> u8 {
        self.inv[token]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sub_builder_new_empty() {
        let cipher = SubstitutionBuilder::new().into_cipher();

        for b in 0..=u8::MAX {
            assert_eq!(b, cipher.encipher(b));
            assert_eq!(b, cipher.decipher(b));
        }
    }

    #[test]
    fn sub_builder_rotate_forward() {
        // Check that every possible shift value is handled correctly.
        for offset in 0..=u8::MAX {
            let mut builder = SubstitutionBuilder::new();
            builder.rotate_range(0, u8::MAX, offset as isize);
            let cipher = builder.into_cipher();

            // Check that all bytes are ciphered correctly for the shift.
            for b in 0..=u8::MAX {
                let enc = cipher.encipher(b);
                assert_eq!(b.wrapping_add(offset), enc);
                assert_eq!(b, cipher.decipher(enc));
            }
        }
    }

    #[test]
    fn sub_builder_rotate_backward() {
        // Check that every possible shift value is handled correctly.
        for offset in -(u8::MAX as i16)..=0 {
            let mut builder = SubstitutionBuilder::new();
            builder.rotate_range(0, u8::MAX, offset as isize);
            let cipher = builder.into_cipher();

            // Check that all bytes are ciphered correctly for the shift.
            for b in 0..=u8::MAX {
                let enc = cipher.encipher(b);
                assert_eq!(b.wrapping_sub(offset.abs() as u8), enc);
                assert_eq!(b, cipher.decipher(enc));
            }
        }
    }

    #[test]
    fn sub_builder_rotate_only_affects_inclusive_range() {
        let test_range = (b'A', b'Z');
        let offset = 2;

        let mut builder = SubstitutionBuilder::new();
        builder.rotate_range(test_range.0, test_range.1, offset);
        let cipher = builder.into_cipher();

        // Check that only the bytes in the rotated range have been shifted
        for b in 0..=u8::MAX {
            let expected = if b <= test_range.1 && b >= test_range.0 {
                test_range.0 + (b - test_range.0 + offset as u8) % (1 + test_range.1 - test_range.0)
            } else {
                b
            };
            assert_eq!(cipher.encipher(b), expected);
        }
    }

    #[test]
    fn sub_builder_swap() {
        let mut builder = SubstitutionBuilder::new();

        let mappings = [
            (b'a', b'b'), // a->b, b->a
            (b'b', b'c'), // c->a, b->c, a->b
            (b'd', b'e'), // c->a, b->c, a->b, d->e, e->d
            (b'd', b'c'), // d->a, c->e, b->c, a->b, e->d
        ];

        for (left, right) in mappings.iter() {
            builder.swap(*left, *right);
        }

        let cipher = builder.into_cipher();

        assert_eq!(b'a', cipher.encipher(b'd'));
        assert_eq!(b'b', cipher.encipher(b'a'));
        assert_eq!(b'c', cipher.encipher(b'b'));
        assert_eq!(b'd', cipher.encipher(b'e'));
        assert_eq!(b'e', cipher.encipher(b'c'));
    }

    #[test]
    fn sub_builder_new_matches_cipher_default() {
        let ciphers = (
            SubstitutionBuilder::new().into_cipher(),
            SubstitutionCipher::default(),
        );

        for b in 0..=u8::MAX {
            assert_eq!(
                ciphers.0.encipher(b),
                ciphers.1.encipher(b),
            )
        }
    }
}