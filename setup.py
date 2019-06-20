#!/usr/bin/python

import setuptools
import os

version = {}
with open(os.path.join('stormshield', 'sns', 'sslclient', '__version__.py'), 'r') as fh:
    exec(fh.read(), version)

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="stormshield.sns.sslclient",
    version=version['__version__'],
    author="Remi Pauchet",
    author_email="remi.pauchet@stormshield.eu",
    description="SSL API client for Stormshield Network Security appliances",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/stormshield/python-SNS-API",
    license='Apache License 2.0',
    packages=setuptools.find_packages(),
    entry_points={
        'console_scripts': ['snscli=stormshield.sns.cli:main'],
    },
    install_requires=[
        'pygments',
        'requests[socks]',
        'requests_toolbelt',
        'colorlog',
        'defusedxml',
        'pyreadline; platform_system == "Windows"',
        'py2-ipaddress; python_version < "3"'
    ],
    include_package_data=True,
    tests_require=["nose"],
    test_suite='nose.collector',
    classifiers=[
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Topic :: System :: Networking",
        "Environment :: Console"
    ],
)
