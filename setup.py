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
        'cos-python-sdk-v5>=1.7.4',
        'cryptography>=2.8',
        'lz4>=2.2.1',
        'toml>=0.10.0',
    ],
)
