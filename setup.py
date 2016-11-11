# -*- coding: utf-8 -*-
import os
import sys

from setuptools import setup, find_packages

py_version = sys.version_info[:2]
if py_version < (3, 5):
    raise Exception("aiohttp requires Python >= 3.5.")


here = os.path.abspath(os.path.dirname(__file__))
NAME = 'plone.oauth'
with open(os.path.join(here, 'README.rst')) as readme:
    README = readme.read()
with open(os.path.join(here, 'CHANGES.rst')) as changes:
    CHANGES = changes.read()

requires = [
    'aiohttp',
    'aiohttp_cors',
    'aiohttp_jinja2',
    'pycrypto',
    'ecdsa',
    'aioredis',
    'aiohttp_swagger',
    'ujson',
    'ldap3',
    'pyjwt',
    'requests',
    'pyramid_mailer',
    'validate_email',
]

setup(
    name=NAME,
    version='1.0',
    description='Plone OAuth',
    long_description=README + '\n\n' + CHANGES,
    classifiers=[
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.5",
        "Framework :: Aiohttp",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Application",
    ],
    author='',
    author_email='',
    url='',
    keywords='aiohttp asyncio web wsgi',
    packages=find_packages(),
    namespace_packages=['plone'],
    include_package_data=True,
    zip_safe=False,
    test_suite=NAME,
    install_requires=requires,
    extras_require={
        'test': [
            'psutil',
            'pytest',
        ],
    },
    entry_points="""\
    [paste.app_factory]
    main = plone.oauth:main
    """,
)
