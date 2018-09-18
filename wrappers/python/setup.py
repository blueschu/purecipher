from distutils.core import setup, Extension

purecipher_module = Extension('purecipher', sources=['purecipher/pureciphermodule.c'])

setup(
    name='purecipher',
    version='0.1.0',
    ext_modules=[purecipher_module],
)
