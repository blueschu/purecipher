#include "Python.h"

static PyMethodDef purecipher_Methods[] = {
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static struct PyModuleDef spammodule = {
    PyModuleDef_HEAD_INIT,
    "purecipher",   /* name of module */
    NULL,           /* module documentation, may be NULL */
    -1,             /* size of per-interpreter state of the module,
                    or -1 if the module keeps state in global variables. */
    purecipher_Methods,
};

PyMODINIT_FUNC
PyInit_purecipher(void)
{
    PyObject *module;

    module = PyModule_Create(&spammodule);
    if (module == NULL)
        return NULL;

    // perform other module initiation steps

    return module;
}
