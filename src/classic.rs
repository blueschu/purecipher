//! A collection of classic pure ciphers.

use super::{SubstitutionBuilder, SubstitutionCipher};

/// Builds the classic caesar cipher.
///
/// # Example
/// ```
/// let caesar = purecipher::caesar();
/// let message = "We attack at dawn.";
///
/// let cipher_text = purecipher::encipher_bytes(&caesar, &message);
/// assert_eq!("Zh dwwdfn dw gdzq.".as_bytes(), &cipher_text[..]);
/// ```
pub fn caesar() -> SubstitutionCipher {
    let mut builder = SubstitutionBuilder::new();
    builder.rotate_range(b'A', b'Z', 3);
    builder.rotate_range(b'a', b'z', 3);
    builder.into_cipher()
}

/// Builds the rot13 substitution cipher.
///
/// # Example
/// ```
/// let rot13 = purecipher::rot13_alpha();
/// let message = "Lovely plumage, the Norwegian Blue.";
///
/// let cipher_text = purecipher::encipher_bytes(&rot13, &message);
/// assert_eq!("Ybiryl cyhzntr, gur Abejrtvna Oyhr.".as_bytes(), &cipher_text[..]);
pub fn rot13_alpha() -> SubstitutionCipher {
    let mut builder = SubstitutionBuilder::new();
    builder.rotate_range(b'A', b'Z', 13);
    builder.rotate_range(b'a', b'z', 13);
    builder.into_cipher()
}

/// Builds a rough cipher to stereotypical "leet" speak.
///
/// # Example
/// ```
/// let leet = purecipher::leet_speak();
/// let message = "Pure ciphers are the BEST!";
///
/// let cipher_text = purecipher::encipher_bytes(&leet, &message);
/// assert_eq!("Pur3 c!ph3rs @r3 1h3 BE5Ti".as_bytes(), &cipher_text[..]);
/// ```
pub fn leet_speak() -> SubstitutionCipher {
    let substitutions = [
        (b'a', b'@'),
        (b'e', b'3'),
        (b'A', b'4'),
        (b'S', b'5'),
        (b'i', b'!'),
        (b't', b'1'),
    ];

    let mut builder = SubstitutionBuilder::new();
    for (token, target) in substitutions.iter() {
        builder.swap(*token, *target);
    }

    builder.into_cipher()
}