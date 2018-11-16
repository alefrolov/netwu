#!/usr/bin/env python3
from setuptools import setup, find_packages

setup(
    name='netwu',
    version='1.0',
    packages=find_packages(),
    long_description='Simple network utility',
    entry_points={
        'console_scripts':[
            'netwu = netwu.netwu:main'
        ]
    }
)