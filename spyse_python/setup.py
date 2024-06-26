#!/usr/bin/python3
from setuptools import setup, find_packages

with open('README.md') as f:
    readme = f.read()

with open('LICENSE.md') as f:
    spyse_license = f.read()

setup(
    name='spyse_python',
    version='2.2.4',
    description='Python wrapper for spyse.com',
    long_description=readme,
    long_description_content_type='text/markdown',
    author='Roman Romanov',
    author_email='roman.romanov@spyse.com',
    url='https://github.com/spyse-com/spyse-python',
    license=spyse_license,
    packages=find_packages(exclude=('tests', 'examples')),
    python_requires='>=3.7',
    install_requires=['requests>=2.28.0', 'dataclasses-json~=0.5.4', 'responses>=0.13.3',
                      'limiter>=0.1.2']
)
