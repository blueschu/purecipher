#include "cipher.h"

static void Cipher_dealloc(PureCipher_CipherObject *self) {
    purecipher_free(self->cipher);
    Py_TYPE(self)->tp_free((PyObject *) self);
}

static PyObject *Cipher_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
    PureCipher_CipherObject *self;
    self = (PureCipher_CipherObject *) type->tp_alloc(type, 0);
    if (self != NULL) {
        self->cipher = purecipher_cipher_null();
    }
    return (PyObject *) self;
}

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

static PyMethodDef Cipher_methods[] = {
    {"encipher", (PyCFunction) Cipher_encipher_str, METH_VARARGS, PyDoc_STR("encipher(str)")},
    {"decipher", (PyCFunction) Cipher_decipher_str, METH_VARARGS, PyDoc_STR("decipher(strr)")},
    {NULL}  /* Sentinel */
};

PyTypeObject PureCipher_CipherType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "purecipher.Cipher",
    .tp_doc = "Pure (stateless) cipher",
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
