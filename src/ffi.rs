//! C API for purecipher
//!
//! See the associated C header file for interface documentation.

use std::slice;

use libc::size_t;

use super::PureCipher;

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

    #[test]
    fn cipher_buffer_reversible() {
        let cipher_ptr = purecipher_cipher_rot13();
        let text = "these are some bytes";
        let mut buffer = Vec::from(text);

        purecipher_encipher_buffer(
            cipher_ptr,
            buffer.as_mut_slice().as_mut_ptr(),
            buffer.len()
        );
        assert_ne!(text.as_bytes(), buffer.as_slice());

        purecipher_decipher_buffer(
            cipher_ptr,
            buffer.as_mut_slice().as_mut_ptr(),
            buffer.len()
        );
        assert_eq!(text.as_bytes(), buffer.as_slice());
        purecipher_free(cipher_ptr);
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
            buffer.len()
        );
        assert_eq!(output.as_ref(), buffer.as_slice());
    }
}
