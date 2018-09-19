#ifndef PURECIPHER_CIPHER_H
#define PURECIPHER_CIPHER_H

#include "Python.h"

#include "purecipher.h"

/*
 * Python object wrapping a pure cipher object pointer.
 */
typedef struct {
    PyObject_HEAD
    purecipher_obj_t cipher;
} PureCipher_CipherObject;

/*
 * Python type object singleton for PureCipher_CipherObjects.
 */
extern PyTypeObject PureCipher_CipherType;

/*
 * Overwrite the cipher used by the given PureCipher_CipherObject, freeing the
 * previous cipher.
 */
void PureCipher_Cipher_set_cipher(PureCipher_CipherObject *self, purecipher_obj_t new_cipher);

#endif //PURECIPHER_CIPHER_H
