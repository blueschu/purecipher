#include "Python.h"

#include "builder.h"
#include "cipher.h"

/*
 * Build an owned PureCipher_CipherObject for caesar cipher encoding.
 */
static PyObject *make_cipher_caesar(PyObject *Py_UNUSED(self), PyObject *Py_UNUSED(args)) {
    PyObject *cipher = PyObject_CallObject((PyObject *) &PureCipher_CipherType, NULL);
    if (cipher != NULL) {
        PureCipher_Cipher_set_cipher((PureCipher_CipherObject *) cipher, purecipher_cipher_caesar());
    }
    return cipher;
}

const PyDoc_STRVAR(make_cipher_caesar_doc,
    "caesar()\n\nReturn a pure cipher that shifts ASCII letters three ahead.");

/*
 * Build an owned PureCipher_CipherObject for rot13 encoding.
 */
static PyObject *make_cipher_rot13(PyObject *Py_UNUSED(self), PyObject *Py_UNUSED(args)) {
    PyObject *cipher = PyObject_CallObject((PyObject *) &PureCipher_CipherType, NULL);
    if (cipher != NULL) {
        PureCipher_Cipher_set_cipher((PureCipher_CipherObject *) cipher, purecipher_cipher_rot13());
    }
    return cipher;
}

const PyDoc_STRVAR(make_cipher_rot13_doc,
    "rot13()\n\nReturn a pure cipher that performs rot13 encoding on ASCII letters.");

/*
 * Build an owned PureCipher_CipherObject for "leet speak" encoding.
 */
static PyObject *make_cipher_leet(PyObject *Py_UNUSED(self), PyObject *Py_UNUSED(args)) {
    PyObject *cipher = PyObject_CallObject((PyObject *) &PureCipher_CipherType, NULL);
    if (cipher != NULL) {
        PureCipher_Cipher_set_cipher((PureCipher_CipherObject *) cipher, purecipher_cipher_leet());
    }
    return cipher;
}

const PyDoc_STRVAR(make_cipher_leet_doc,
    "leet()\n\nReturn a rough pure cipher for stereotypical \"leet\" speak.");

/* Module docstring. */
const PyDoc_STRVAR(PureCipher_Docstring, "Python bindings to the Rust purecipher crate.");

/* Module methods. */
static PyMethodDef PureCipher_Methods[] = {
    {"caesar", make_cipher_caesar, METH_NOARGS, make_cipher_caesar_doc},
    {"rot13",  make_cipher_rot13,  METH_NOARGS, make_cipher_rot13_doc},
    {"leet",   make_cipher_leet,   METH_NOARGS, make_cipher_leet_doc},
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
    if (PyType_Ready(&PureCipher_BuilderType) < 0) {
        return NULL;
    }

    /* Create the module. */
    module = PyModule_Create(&PureCipher_Module);
    if (module == NULL) {
        return NULL;
    }

    /* Exception type initialization */
    PureCipher_BuilderError = PyErr_NewExceptionWithDoc(
        "purecipher.BuilderError",
        PyDoc_STR("Python Exception type raised for errors in SubstitutionBuilder instances."),
        NULL,
        NULL
    );

    /*  Add objects to module */
    Py_INCREF(&PureCipher_CipherType);
    PyModule_AddObject(module, "Cipher", (PyObject *) &PureCipher_CipherType);

    Py_INCREF(&PureCipher_BuilderType);
    PyModule_AddObject(module, "SubstitutionBuilder", (PyObject *) &PureCipher_BuilderType);

    Py_INCREF(PureCipher_BuilderError);
    PyModule_AddObject(module, "BuilderError", PureCipher_BuilderError);

    return module;
}
