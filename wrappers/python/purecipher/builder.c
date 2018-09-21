#include "builder.h"

#include "cipher.h"

/*
 * Python Exception type raised for errors in PureCipher_BuilderObject methods.
 */
PyObject *PureCipher_BuilderError;

/*
 * Destructor for PureCipher_BuilderObject.
 */
static void Builder_dealloc(PureCipher_BuilderObject *self) {
    if (self->builder != NULL) {
        purecipher_builder_discard(self->builder);
    }
    Py_TYPE(self)->tp_free((PyObject *) self);
}

/*
 * Constructor for PureCipher_BuilderObject.
 */
static PyObject *Builder_new(PyTypeObject *type, PyObject *Py_UNUSED(args), PyObject *Py_UNUSED(kwds)) {
    PureCipher_BuilderObject *self;
    self = (PureCipher_BuilderObject *) type->tp_alloc(type, 0);
    if (self != NULL) {
        self->builder = purecipher_builder_new();
    }
    return (PyObject *) self;
}

/*
 * Checks if the given builder object has been consumed.
 */
static PyObject *Builder_is_consumed(PureCipher_BuilderObject *self, PyObject *Py_UNUSED(args)) {
    if (self->builder == NULL) {
        Py_RETURN_TRUE;
    }
    Py_RETURN_FALSE;
}

const PyDoc_STRVAR(Builder_is_consumed_doc,
    "Return True if this builder has been consumed, False otherwise.");

/*
 * Convert a substitution builder into a cipher object.
 */
static PyObject *Builder_into_cipher(PureCipher_BuilderObject *self, PyObject *Py_UNUSED(args)) {
    if (PureCipher_BuilderObject_check_consumed(self) < 0) {
        return NULL;
    }
    const purecipher_obj_t cipher_ptr = purecipher_builder_into_cipher(self->builder);
    self->builder = NULL;

    PyObject *cipher = PyObject_CallObject((PyObject *) &PureCipher_CipherType, NULL);
    if (cipher != NULL) {
        PureCipher_Cipher_set_cipher((PureCipher_CipherObject *) cipher, cipher_ptr);
    }
    return cipher;
}

const PyDoc_STRVAR(Builder_into_cipher_doc,
    "Convert this substitution builder into a cipher object.\n\n"
    "This method will consume this builder. Further configuration will not be possible.");

/*
 * Swap two bytes in the cipher mapping that this builder will produce.
 */
static PyObject *Builder_swap(PureCipher_BuilderObject *self, PyObject *args) {
    uint8_t left;
    uint8_t right;
    if (!PyArg_ParseTuple(args, "cc", &left, &right)) {
        return NULL;
    }
    if (PureCipher_BuilderObject_check_consumed(self) < 0) {
        return NULL;
    }
    purecipher_builder_swap(self->builder, left, right);

    Py_INCREF(self);
    return (PyObject *) self;
}

const PyDoc_STRVAR(Builder_swap_doc,
    "swap(left, right)"
    "\n\n"
    "Swap the two given bytes in the cipher mapping that this builder will"
    "produce."
    "\n\n"
    "This function actions two Python bytes, represented as bytes or bytearray "
    "objects of length 1.");

/*
 * Rotates each byte in the given inclusive range by the given offset in the
 * cipher mapping that this builder will produce.
 */
static PyObject *Builder_rotate(PureCipher_BuilderObject *self, PyObject *args) {
    uint8_t from;
    uint8_t to;
    int32_t offset;
    if (!PyArg_ParseTuple(args, "cci", &from, &to, &offset)) {
        return NULL;
    }
    if (PureCipher_BuilderObject_check_consumed(self) < 0) {
        return NULL;
    }
    purecipher_builder_rotate(self->builder, from, to, offset);

    Py_INCREF(self);
    return (PyObject *) self;
}

const PyDoc_STRVAR(Builder_rotate_doc,
    "rotate(from, to, offset)"
    "\n\n"
    "Rotates each byte in the given inclusive range by the given offset in the\n"
    "cipher mapping that this builder will produce.");

/*
 * PureCipher_BuilderObject method description tables.
 */
static PyMethodDef Builder_methods[] = {
    {"is_consumed", (PyCFunction) Builder_is_consumed, METH_NOARGS,  Builder_is_consumed_doc},
    {"into_cipher", (PyCFunction) Builder_into_cipher, METH_NOARGS,  Builder_into_cipher_doc},
    {"swap",        (PyCFunction) Builder_swap,        METH_VARARGS, Builder_swap_doc},
    {"rotate",      (PyCFunction) Builder_rotate,      METH_VARARGS, Builder_rotate_doc},
    {NULL}  /* Sentinel */
};

const PyDoc_STRVAR(PureCipher_BuilderObject_doc,
    "Helper object to builder substitution based pure ciphers."
    "\n\n"
    "This object is single use: one builder can only produce one substitution cipher.\n"
    "This is intentional. Adding an interface for copying cipher or builder instances\n"
    "to the purecipher API was deemed unnecessary as it serves only to demonstrate the\n"
    "design of FFI interfaces and is not intended for practical application.");

/*
 * Python type object for PureCipher_BuilderObject instances.
 */
PyTypeObject PureCipher_BuilderType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "purecipher.SubstitutionBuilder",
    .tp_doc = PureCipher_BuilderObject_doc,
    .tp_basicsize = sizeof(PureCipher_BuilderObject),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_new = Builder_new,
    .tp_dealloc = (destructor) Builder_dealloc,
    .tp_methods = Builder_methods,
};

int PureCipher_BuilderObject_check_consumed(const PureCipher_BuilderObject *self) {
    if (self->builder == NULL) {
        PyErr_SetString(PureCipher_BuilderError, "Builder has already been consumed.");
        return -1;
    }
    return 0;
}
