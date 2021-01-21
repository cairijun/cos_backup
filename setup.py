#!/usr/bin/env python
from setuptools import setup, find_packages

setup(
    name='cos_backup',
    version='1.0',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'cos_backup = cos_backup:main',
        ],
    },
    python_requires='>=3.7',
    install_requires=[
        'cos-python-sdk-v5>=1.7.4,<1.9.0',
        'cryptography>=3.3.1',
        'lz4>=3.1.1',
        'toml>=0.10.2',
    ],
)
