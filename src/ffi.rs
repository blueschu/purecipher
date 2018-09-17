//! C API for purecipher
//!
//! See the associated C header file for interface documentation.

use std::slice;
use std::ffi::CStr;

use libc::{c_char, size_t, int32_t};

use super::{PureCipher, SubstitutionBuilder};

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq)]
/// Type for PureCipher trait object pointers to be passed over ffi.
pub struct CipherObject {
    /// Fat pointer to cipher trait object.
    ptr: *const dyn PureCipher,
}

#[no_mangle]
pub extern "C" fn purecipher_free(cipher: CipherObject) {
    unsafe {
        Box::from_raw(cipher.ptr as *mut PureCipher);
    }
}

#[no_mangle]
pub extern "C" fn purecipher_encipher_buffer(cipher: CipherObject, buffer: *mut u8, length: size_t) {
    if cipher.ptr.is_null() || buffer.is_null() {
        return;
    }

    let cipher_ref = unsafe { &*cipher.ptr };
    let slice = unsafe {
        slice::from_raw_parts_mut(buffer, length)
    };

    cipher_ref.encipher_inplace(slice)
}

#[no_mangle]
pub extern "C" fn purecipher_decipher_buffer(cipher: CipherObject, buffer: *mut u8, length: size_t) {
    if cipher.ptr.is_null() || buffer.is_null() {
        return;
    }

    let cipher_ref = unsafe { &*cipher.ptr };
    let slice = unsafe {
        slice::from_raw_parts_mut(buffer, length)
    };

    cipher_ref.decipher_inplace(slice)
}

#[no_mangle]
pub extern "C" fn purecipher_encipher_str(cipher: CipherObject, s: *mut c_char) {
    // Compute length of null-terminated string.
    let s_ref = unsafe { CStr::from_ptr(s) };
    // Trailing null byte is not encoded.
    purecipher_encipher_buffer(cipher, s as *mut u8, s_ref.to_bytes().len())
}

#[no_mangle]
pub extern "C" fn purecipher_decipher_str(cipher: CipherObject, s: *mut c_char) {
    // Compute length of null-terminated string.
    let s_ref = unsafe { CStr::from_ptr(s) };
    // Trailing null byte is not decoded.
    purecipher_decipher_buffer(cipher, s as *mut u8, s_ref.to_bytes().len())
}

#[no_mangle]
pub extern "C" fn purecipher_builder_new() -> *mut SubstitutionBuilder {
    let builder = Box::new(SubstitutionBuilder::new());
    Box::into_raw(builder)
}

#[no_mangle]
pub extern "C" fn purecipher_builder_swap(builder: *mut SubstitutionBuilder, left: u8, right: u8) {
    let builder_ref = unsafe { &mut *builder };
    builder_ref.swap(left, right)
}

#[no_mangle]
pub extern "C" fn purecipher_builder_rotate(builder: *mut SubstitutionBuilder, from: u8, to: u8, offset: int32_t) {
    let builder_ref = unsafe { &mut *builder };
    builder_ref.rotate_range(from, to, offset as isize)
}

#[no_mangle]
pub extern "C" fn purecipher_builder_into_cipher(builder: *mut SubstitutionBuilder) -> CipherObject {
    // No null pointer check is performed against the builder as no sensible
    // error value can be returned. It is the caller's responsibility to pass a
    // valid builder.
    let builder_box = unsafe { Box::from_raw(builder) };
    let cipher_ptr = Box::new(builder_box.into_cipher());
    CipherObject { ptr: Box::into_raw(cipher_ptr) }
}

#[no_mangle]
pub extern "C" fn purecipher_builder_discard(builder: *mut SubstitutionBuilder) {
    unsafe {
        Box::from_raw(builder);
    }
}

#[no_mangle]
pub extern "C" fn purecipher_cipher_caesar() -> CipherObject {
    let cipher_ptr = Box::new(super::caesar());
    CipherObject { ptr: Box::into_raw(cipher_ptr) }
}

#[no_mangle]
pub extern "C" fn purecipher_cipher_rot13() -> CipherObject {
    let cipher_ptr = Box::new(super::rot13_alpha());
    CipherObject { ptr: Box::into_raw(cipher_ptr) }
}

#[no_mangle]
pub extern "C" fn purecipher_cipher_leet() -> CipherObject {
    let cipher_ptr = Box::new(super::leet_speak());
    CipherObject { ptr: Box::into_raw(cipher_ptr) }
}

#[no_mangle]
pub extern "C" fn purecipher_cipher_null() -> CipherObject {
    let cipher_ptr = Box::new(super::NullCipher {});
    CipherObject { ptr: Box::into_raw(cipher_ptr) }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::CString;

    #[test]
    fn cipher_buffer_reversible() {
        let cipher_ptr = purecipher_cipher_rot13();
        let text = "these are some bytes";
        let mut buffer = Vec::from(text);

        purecipher_encipher_buffer(
            cipher_ptr,
            buffer.as_mut_slice().as_mut_ptr(),
            buffer.len(),
        );
        assert_ne!(text.as_bytes(), buffer.as_slice());

        purecipher_decipher_buffer(
            cipher_ptr,
            buffer.as_mut_slice().as_mut_ptr(),
            buffer.len(),
        );
        assert_eq!(text.as_bytes(), buffer.as_slice());
        purecipher_free(cipher_ptr);
    }

    #[test]
    fn cipher_c_str() {
        // Cipher to increment all bytes by 1.
        let cipher_ptr = {
            let mut builder = SubstitutionBuilder::new();
            builder.rotate_range(0, 255, 1);
            let cipher = builder.into_cipher();
            CipherObject { ptr: Box::into_raw(Box::new(cipher)) }
        };

        let message = CString::new("I do not want to buy this record.").unwrap();
        assert_eq!(b"I do not want to buy this record.\0".as_ref(), message.as_bytes_with_nul());

        purecipher_encipher_str(cipher_ptr, message.as_ptr() as *mut c_char);
        assert_eq!(b"J!ep!opu!xbou!up!cvz!uijt!sfdpse/\0".as_ref(), message.as_bytes_with_nul());

        purecipher_decipher_str(cipher_ptr, message.as_ptr() as *mut c_char);
        assert_eq!(b"I do not want to buy this record.\0".as_ref(), message.as_bytes_with_nul());
    }

    #[test]
    fn cipher_c_str_empty() {
        // No need to perform any ciphering
        let cipher_ptr = purecipher_cipher_null();

        let message = CString::new("").unwrap();
        assert_eq!(b"\0".as_ref(), message.as_bytes_with_nul());

        purecipher_encipher_str(cipher_ptr, message.as_ptr() as *mut c_char);
        assert_eq!(b"\0".as_ref(), message.as_bytes_with_nul());
    }

    #[test]
    fn encipher_buffer_length_lte_1() {
        struct SetAll;
        impl PureCipher for SetAll {
            fn encipher(&self, _token: u8) -> u8 { b'A' }
            fn decipher(&self, _token: u8) -> u8 { unimplemented!() }
        }

        let cipher_ptr = CipherObject { ptr: Box::into_raw(Box::new(SetAll {}))};
        let mut buf = [b'B'; 2];

        purecipher_encipher_buffer(cipher_ptr, buf.as_mut_ptr(), 0);
        assert_eq!(b"BB", buf.as_ref());

        purecipher_encipher_buffer(cipher_ptr, buf.as_mut_ptr(), 1);
        assert_eq!(b"AB", buf.as_ref());
    }

    #[test]
    fn cipher_caesar() {
        let cipher_ptr = purecipher_cipher_caesar();

        assert_cipher_buffer(
            cipher_ptr,
            "Permission is hereby granted, free of charge...",
            "Shuplvvlrq lv khuheb judqwhg, iuhh ri fkdujh...",
        );

        purecipher_free(cipher_ptr);
    }

    #[test]
    fn cipher_rot13() {
        let cipher_ptr = purecipher_cipher_rot13();

        assert_cipher_buffer(
            cipher_ptr,
            "Permission is hereby granted, free of charge...",
            "Crezvffvba vf urerol tenagrq, serr bs punetr...",
        );

        purecipher_free(cipher_ptr);
    }

    #[test]
    fn cipher_leet() {
        let cipher_ptr = purecipher_cipher_leet();

        assert_cipher_buffer(
            cipher_ptr,
            "Permission is hereby granted, free of charge...",
            "P3rm!ss!on !s h3r3by gr@n13d, fr33 of ch@rg3...",
        );

        purecipher_free(cipher_ptr);
    }

    /// Asserts that the `cipher` produces the given `output` bytes when applied
    /// to a buffer of `input` bytes.
    fn assert_cipher_buffer<T, U>(cipher: CipherObject, input: T, output: U)
        where T: AsRef<[u8]>,
              U: AsRef<[u8]>,
    {
        let mut buffer = Vec::from(input.as_ref());
        purecipher_encipher_buffer(
            cipher,
            buffer.as_mut_slice().as_mut_ptr(),
            buffer.len(),
        );
        assert_eq!(output.as_ref(), buffer.as_slice());
    }
}
