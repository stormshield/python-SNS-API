#!/usr/bin/python

import setuptools

import stormshield.sns


with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="stormshield.sns.sslclient",
    version=stormshield.sns.__version__,
    author="Remi Pauchet",
    author_email="remi.pauchet@stormshield.eu",
    description="SSL API client for Stormshield Network Security appliances",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/stormshield/python-SNS-API",
    license='Apache License 2.0',
    packages=setuptools.find_packages(),
    scripts=['bin/snscli'],
    install_requires=[
        'pygments',
        'begins',
        'requests',
        'requests_toolbelt',
        'colorlog',
        'pyreadline; platform_system == "Windows"'
    ],
    include_package_data=True,
    tests_require=["nose"],
    test_suite='nose.collector',
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: Apache License 2.0",
        "Operating System :: OS Independent",
        'Topic :: System :: Networking'
        'Environment :: Console'
    ],
)
