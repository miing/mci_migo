# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from setuptools import setup


setup(
    name="canonical-identity-provider",
    version="2.7.1.dev3",

    author="Canonical ISD Hackers",
    author_email="canonical-isd@lists.launchpad.net",

    license="AGPLv3",

    packages=['sso_mockserver'],

    zip_safe=False,

    package_data={'sso_mockserver': ['wadl.xml']},
)
