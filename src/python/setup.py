__author__ = 'tom'

from setuptools import setup, find_namespace_packages

# To build for local development use 'python setup.py develop'.
# To upload a version to pypi use 'python setup.py clean sdist upload'.
# Docs are built with 'make html' in the docs directory parallel to this one
setup(
    name='approxeng.reimage',
    version='0.0.1',
    description='Library to modify SD card images, in particular for the Raspbery Pi OS',
    classifiers=['Programming Language :: Python :: 3.7'],
    url='https://github.com/ApproxEng/approxeng.reimage/',
    author='Tom Oinn',
    author_email='tomoinn@gmail.com',
    license='ASL2.0',
    packages=find_namespace_packages(),
    install_requires=[])
