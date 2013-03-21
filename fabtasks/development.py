import os
from urlparse import urlparse

from fabric.api import local, settings

from .database import createdb, dropdb, setup_db_access
from .django import (
    get_django_settings,
    manage,
    syncdb,
)
from .environment import bootstrap, virtualenv_local


class ArgumentError(Exception):
    pass


def is_staging(url):
    if url is not None:
        url.rstrip('/')
    return url in [
        'https://login.staging.ubuntu.com',
        'https://login.staging.launchpad.net',
    ]


def is_production(url):
    if url is not None:
        url.rstrip('/')
    return url in [
        'https://login.ubuntu.com',
        'https://login.launchpad.net',
    ]


def is_devel():
    url = os.getenv('SST_BASE_URL', None)
    return url is None or not (is_staging(url) or is_production(url))


def test(coverage=False, extra=''):
    """Run unit tests."""
    cmd = ['python django_project/manage.py test --noinput', extra]
    virtualenv_local(' '.join(cmd), capture=False)


def _is_true(arg, name):
    if arg.lower() in ('t', 'true', 'on', '1', 'yes'):
        return True
    elif arg.lower() in ('f', 'false', 'off', '0', 'no'):
        return False
    raise ArgumentError(
        "Argument {!r} should be boolean, was {!r}".format(name, arg))


def acceptance(headless='true', screenshot='false', report='', quiet='true',
        failfast='false', testcase='', flags=None, tests='', debug='false',
        extended='false'):
    """Run acceptance tests only."""

    extended = _is_true(extended, 'extended')
    headless = _is_true(headless, 'headless')
    quiet = _is_true(quiet, 'quiet')
    screenshot = _is_true(screenshot, 'screenshot')
    failfast = _is_true(failfast, 'failfast')
    directory = '-d identityprovider/tests/acceptance/%s' % tests
    debug = _is_true(debug, 'debug')

    cmd = ['DJANGO_SETTINGS_MODULE=django_project.settings PYTHONPATH=.:lib',
           'sst-run']
    if extended:
        cmd.append('--extended-tracebacks')
    if headless:
        cmd.append('-x')
    if screenshot:
        cmd.append('-s')
    if report:
        cmd.append('-r %s' % report)
    if failfast:
        cmd.append('--failfast')
    if testcase:
        cmd.append(testcase)
    if flags is not None:
        flags = flags.strip(';')
        cmd.append('--with-flags="%s"' % flags.replace(';', ','))
    if quiet:
        cmd.append('-q')
    if debug:
        cmd.append('--debug')

    cmd.append(directory)
    virtualenv_local(' '.join(cmd), capture=False)


def apitests():
    """Run API tests only."""
    manage(
        "test --testing_test_discover_root='./identityprovider/tests/api'")


def run(*args, **kwargs):
    """Run SSO using devserver."""
    if not args:
        parsed = urlparse(get_django_settings('SSO_ROOT_URL')['SSO_ROOT_URL'])
        args = [parsed.netloc]
    manage('runserver', *args, **kwargs)


def gargoyle_flags(*args):
    """Define and set the specified gargoyle flags.

    This allows setting up the server (via the database) in a specific
    configuration.  You probably want to call `resetdb` first to ensure you set
    only the relevant flags.
    """
    error_msg = 'json file %r does not exist (current working dir is %r)'
    for a in args:
        json_file = os.path.join('identityprovider', 'fixtures', a + '.json')
        assert os.path.exists(json_file), error_msg % (json_file, os.getcwd())
    manage('loaddata', *args)


def resetdb():
    """Drop and recreate then sync the database."""
    with settings(hide='warnings'):
        dropdb(warn_only=True)
    createdb()
    syncdb()
    setup_db_access()


def jenkins():
    """Run the tests for jenkins."""
    bootstrap()
    # use the system's database
    local("sed -i 's/db_host = .*/db_host =/g' django_project/local.cfg")
    resetdb()
    manage('loaddata test')
    manage("jenkins --testing_test_discover_root=''")


def docs():
    virtualenv_local('sphinx-build docs docs/html')
