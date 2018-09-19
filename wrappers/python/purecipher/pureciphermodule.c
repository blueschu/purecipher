#include "Python.h"

#include "cipher.h"

const PyDoc_STRVAR(make_cipher_caesar_doc, "Return a pure cipher that shifts ASCII letters three ahead.");

static PyObject *make_cipher_caesar(PyObject *self, PyObject *args) {
    PyObject *cipher;
    {
        PyObject *arglist = PyTuple_New(0);
        cipher = PyObject_CallObject((PyObject *) &PureCipher_CipherType, arglist);
        Py_DECREF(arglist);
    }
    if (cipher != NULL) {
        PureCipher_Cipher_set_cipher((PureCipher_CipherObject *) cipher, purecipher_cipher_caesar());
    }
    return cipher;
}

const PyDoc_STRVAR(make_cipher_rot13_doc, "Return a pure cipher that performs rot13 encoding on ASCII letters.");

static PyObject *make_cipher_rot13(PyObject *self, PyObject *args) {
    PyObject *cipher;
    {
        PyObject *arglist = PyTuple_New(0);
        cipher = PyObject_CallObject((PyObject *) &PureCipher_CipherType, arglist);
        Py_DECREF(arglist);
    }
    if (cipher != NULL) {
        PureCipher_Cipher_set_cipher((PureCipher_CipherObject *) cipher, purecipher_cipher_rot13());
    }
    return cipher;
}

const PyDoc_STRVAR(make_cipher_leet_doc, "Return a rough pure cipher for stereotypical \"leet\" speak.");

static PyObject *make_cipher_leet(PyObject *self, PyObject *args) {
    PyObject *cipher;
    {
        PyObject *arglist = PyTuple_New(0);
        cipher = PyObject_CallObject((PyObject *) &PureCipher_CipherType, arglist);
        Py_DECREF(arglist);
    }
    if (cipher != NULL) {
        PureCipher_Cipher_set_cipher((PureCipher_CipherObject *) cipher, purecipher_cipher_leet());
    }
    return cipher;
}

/* Module docstring. */
const PyDoc_STRVAR(PureCipher_Docstring, "Python bindings to the Rust purecipher crate.");

/* Module methods. */
static PyMethodDef PureCipher_Methods[] = {
    {"caesar", make_cipher_caesar, METH_NOARGS, make_cipher_caesar_doc},
    {"rot13",  make_cipher_rot13, METH_NOARGS, make_cipher_rot13_doc},
    {"leet",   make_cipher_leet, METH_NOARGS, make_cipher_leet_doc},
    {NULL, NULL, 0, NULL},  /* Sentinel */
};

/* Module definition. */
static struct PyModuleDef PureCipher_Module = {
    PyModuleDef_HEAD_INIT,
    "purecipher",
    PureCipher_Docstring,
    -1, /* keep state in global variables. */
    PureCipher_Methods,
};

PyMODINIT_FUNC
PyInit_purecipher(void) {
    PyObject *module;

    /* Finalize type objects. */
    if (PyType_Ready(&PureCipher_CipherType) < 0) {
        return NULL;
    }

    /* Create the module. */
    module = PyModule_Create(&PureCipher_Module);
    if (module == NULL) {
        return NULL;
    }

    /*  Add objects to module */
    Py_INCREF(&PureCipher_CipherType);
    PyModule_AddObject(module, "Cipher", (PyObject *) &PureCipher_CipherType);

    return module;
}
