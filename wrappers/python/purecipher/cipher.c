#include "cipher.h"

/*
 * Destructor for PureCipher_CipherObject.
 */
static void Cipher_dealloc(PureCipher_CipherObject *self) {
    purecipher_free(self->cipher);
    Py_TYPE(self)->tp_free((PyObject *) self);
}

/*
 * Constructor for PureCipher_CipherObject.
 */
static PyObject *Cipher_new(PyTypeObject *type, PyObject *Py_UNUSED(args), PyObject *Py_UNUSED(kwds)) {
    PureCipher_CipherObject *self;
    self = (PureCipher_CipherObject *) type->tp_alloc(type, 0);
    if (self != NULL) {
        self->cipher = purecipher_cipher_null();
    }
    return (PyObject *) self;
}

/*
 * Encipher the given string with this cipher.
 */
static PyObject *Cipher_encipher_str(PureCipher_CipherObject *self, PyObject *args) {
    char *clear_data;

    if (!PyArg_ParseTuple(args, "s", &clear_data)) {
        return NULL;
    }

    char *buffer = malloc(strlen(clear_data));
    strcpy(buffer, clear_data);
    purecipher_encipher_str(self->cipher, buffer);

    PyObject *cipher_text = Py_BuildValue("s", buffer);
    free(buffer);
    return cipher_text;
}

const PyDoc_STRVAR(Cipher_encipher_str_doc,
    "encipher(str)"
    "\n\n"
    "Encipher the given string with this cipher."
    "\n\n"
    "This method only accepts Python strings. For operating on byte-like objects\n"
    "inplace, see Cipher.encipher_buffer().");

/*
 * Decipher the given string with this cipher.
 */
static PyObject *Cipher_decipher_str(PureCipher_CipherObject *self, PyObject *args) {
    char *cipher_data;

    if (!PyArg_ParseTuple(args, "s", &cipher_data)) {
        return NULL;
    }

    char *buffer = malloc(strlen(cipher_data));
    strcpy(buffer, cipher_data);
    purecipher_decipher_str(self->cipher, buffer);

    PyObject *clear_text = Py_BuildValue("s", buffer);
    free(buffer);
    return clear_text;
}

const PyDoc_STRVAR(Cipher_decipher_str_doc,
    "decipher(str)"
    "\n\n"
    "Decipher the given string with this cipher."
    "\n\n"
    "This method only accepts Python strings. For operating on byte-like objects\n"
    "inplace, see Cipher.decipher_buffer().");

/*
 * Encipher the given PyByteArrayObject inplace.
 */
static PyObject *Cipher_encipher_buffer(PureCipher_CipherObject *self, PyObject *args) {
    PyByteArrayObject *buffer_object;

    if (!PyArg_ParseTuple(args, "Y", &buffer_object)) {
        return NULL;
    }
    uint8_t *data_buffer = (uint8_t *) PyByteArray_AsString((PyObject *) buffer_object);
    const Py_ssize_t len = PyByteArray_Size((PyObject *) buffer_object);

    purecipher_encipher_buffer(self->cipher, data_buffer, (size_t) len);
    Py_RETURN_NONE;
}

const PyDoc_STRVAR(Cipher_encipher_buffer_doc,
    "encipher_buffer(bytearray)"
    "\n\n"
    "Encipher the given mutable bytearray inplace with this cipher."
    "\n\n"
    "This method only accepts mutable bytearrays. For operating on strings, see\n"
    "Cipher.encipher()");

/*
 * Decipher the given PyByteArrayObject inplace.
 */
static PyObject *Cipher_decipher_buffer(PureCipher_CipherObject *self, PyObject *args) {
    PyByteArrayObject *buffer_object;

    if (!PyArg_ParseTuple(args, "Y", &buffer_object)) {
        return NULL;
    }
    uint8_t *data_buffer = (uint8_t *) PyByteArray_AsString((PyObject *) buffer_object);
    const Py_ssize_t len = PyByteArray_Size((PyObject *) buffer_object);

    purecipher_decipher_buffer(self->cipher, data_buffer, (size_t) len);
    Py_RETURN_NONE;
}

const PyDoc_STRVAR(Cipher_decipher_buffer_doc,
    "decipher_buffer(bytearray)"
    "\n\n"
    "Decipher the given mutable bytearray inplace with this cipher."
    "\n\n"
    "This method only accepts mutable bytearrays. For operating on strings, see\n"
    "Cipher.decipher()");

static PyMethodDef Cipher_methods[] = {
    {"encipher",        (PyCFunction) Cipher_encipher_str,    METH_VARARGS, Cipher_encipher_str_doc},
    {"decipher",        (PyCFunction) Cipher_decipher_str,    METH_VARARGS, Cipher_decipher_str_doc},
    {"encipher_buffer", (PyCFunction) Cipher_encipher_buffer, METH_VARARGS, Cipher_encipher_buffer_doc},
    {"decipher_buffer", (PyCFunction) Cipher_decipher_buffer, METH_VARARGS, Cipher_decipher_buffer_doc},
    {NULL}  /* Sentinel */
};

PyTypeObject PureCipher_CipherType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "purecipher.Cipher",
    .tp_doc = "Pure (stateless) cipher.",
    .tp_basicsize = sizeof(PureCipher_CipherObject),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_new = Cipher_new,
    .tp_dealloc = (destructor) Cipher_dealloc,
    .tp_methods = Cipher_methods,
};

void PureCipher_Cipher_set_cipher(PureCipher_CipherObject *self, const purecipher_obj_t new_cipher) {
    purecipher_obj_t old = self->cipher;
    self->cipher = new_cipher;
    purecipher_free(old);
}
