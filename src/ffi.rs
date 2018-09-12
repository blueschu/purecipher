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
pub extern "C" fn purecipher_cipher_rot13() -> CipherObject {
    let cipher_ptr = Box::new(super::rot13_alpha());
    CipherObject { ptr: Box::into_raw(cipher_ptr) }
}