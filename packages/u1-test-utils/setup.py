from setuptools import (
    find_packages,
    setup,
)

from u1testutils import __version__


setup(name='u1-test-utils',
      version=__version__,
      description="Common testcases and utilities for testing Ubuntu One applications.",
      author='Ricardo Kirkner',
      author_email='ricardo.kirkner@canonical.com',
      packages=find_packages(),
      include_package_data=True,
)
