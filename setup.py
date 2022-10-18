#!/usr/bin/env python3
#
# HEKATOMB - Because Domain Admin rights are not enough. Hack them all.
#
# Author:
#   Processus (@ProcessusT)
#
# Website:
#  https://lestutosdeprocessus.fr


import pathlib
from setuptools import setup, find_packages


HERE = pathlib.Path(__file__).parent
README = (HERE / "README.md").read_text()


setup(
  name='hekatomb',
  version='1.3',
  license='GPL-3.0 license',
  author="Processus Thief",
  author_email='hekatomb@thiefin.fr',
  description="Python library to extract and decrypt all credentials from all domain computers",
  long_description=README,
  long_description_content_type="text/markdown",
  packages=['src'],
  url='https://github.com/Processus-Thief/HEKATOMB',
  keywords='dpapi windows blob masterkey activedirectory credentials',
  platforms='any',
  install_requires=[
    'pycryptodomex',
    'impacket',
    'dnspython',
    'ldap3'
  ],
  entry_points={
        'console_scripts': [
            'hekatomb = src.hekatomb:main',
        ],
    },
  python_requires='>=3.6',
  classifiers=(
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10"
    ),
)