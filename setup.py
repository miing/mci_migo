# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

import os
from setuptools import setup


# This function was taken from the django project.
# Please see the license file in the third-party/django directory.
def fullsplit(path, result=None):
    """
    Split a pathname into components (the opposite of os.path.join) in a
    platform-neutral way.
    """
    if result is None:
        result = []
    head, tail = os.path.split(path)
    if head == '':
        return [tail] + result
    if head == path:
        return result
    return fullsplit(head, [tail] + result)

data_files = []
packages = []
for dirpath, dirnames, filenames in os.walk('identityprovider'):
    # Ignore dirnames that start with '.'
    for i, dirname in enumerate(dirnames):
        if dirname.startswith('.'):
            del dirnames[i]
    if '__init__.py' in filenames:
        packages.append('.'.join(fullsplit(dirpath)))
    elif filenames:
        data_files.append([os.path.join('share', dirpath),
                           [os.path.join(dirpath, f) for f in filenames]])

setup(
    name="canonical-identity-provider",
    version="11.07.12",

    author="Canonical ISD Hackers",
    author_email="canonical-isd@lists.launchpad.net",

    license="AGPLv3",

    zip_safe=False,

    packages=packages,
    package_data={
        'identityprovider.webservice': ['site.zcml'],
    },
    data_files=data_files,

    entry_points={
        'console_scripts': 'sso-account-merge = identityprovider.bin.accounts_merge:main'
    },
)
