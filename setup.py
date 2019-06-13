#!/usr/bin/env python

from distutils.core import setup
from setuptools import find_packages
from pycloudflare_v4 import __version__

setup(
    name='pycloudflare-v4',
    version=__version__,
    description='Python wrapper for CloudFlare API v4',
    url='https://github.com/liwanggui/pycloudflare-v4',
    author='liwanggui',
    author_email='liwg.jx@gmail.com',
    license='MIT',

    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: DevOps, Sysadmins, Developers',
        'Topic :: Tools',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],

    keywords='CludFlare API v4 wrapper',
    packages=find_packages(exclude=['contrib', 'docs', 'tests', 'build', 'dist'])
)