from setuptools import setup, Extension
from glob import glob

purecipher_module = Extension(
    'purecipher',
    sources=glob('purecipher/*.c'),
    include_dirs=['../../include'],
    library_dirs=['../../target/debug'],
    libraries=['purecipher']
)

setup(
    name='purecipher',
    version='0.1.0',
    ext_modules=[purecipher_module],
)
