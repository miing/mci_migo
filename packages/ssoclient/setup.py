from setuptools import setup, find_packages

setup(
    name='ssoclient',
    version='2.0',

    author='Canonical ISD Hackers',
    author_email='canonical-isd@lists.launchpad.net',

    license='AGPLv3',

    packages=find_packages(),
    install_requires=[
        'requests',
        'requests_oauthlib',
    ],

    tests_require=[
        'mock',
    ],
    test_suite='ssoclient.tests',
)
