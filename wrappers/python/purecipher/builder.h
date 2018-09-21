#ifndef PURECIPHER_BUILDER_H
#define PURECIPHER_BUILDER_H

#include "Python.h"

#include "stdbool.h"

#include "purecipher.h"

/*
 * Python object wrapping a substitution builder pointer.
 */
typedef struct {
    PyObject_HEAD
    purecipher_builder_t *builder;
} PureCipher_BuilderObject;

/*
 * Python type object singleton for PureCipher_BuilderObjects.
 */
extern PyTypeObject PureCipher_BuilderType;

/*
 * Python Exception type raised for errors in PureCipher_BuilderObject methods.
 */
extern PyObject *PureCipher_BuilderError;

/*
 * Helper function to raise a python exception if the given builder object has
 * already been consumed.
 *
 * This function returns -1 if an exception was raised, 0 otherwise.
 */
int PureCipher_BuilderObject_check_consumed(const PureCipher_BuilderObject *self);

#endif //PURECIPHER_BUILDER_H
