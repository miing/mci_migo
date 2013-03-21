###################################################################
#
# Copyright (c) 2011 Canonical Ltd.
# Copyright (c) 2013 Miing.org <samuel.miing@gmail.com>
# 
# This software is licensed under the GNU Affero General Public 
# License version 3 (AGPLv3), as published by the Free Software 
# Foundation, and may be copied, distributed, and modified under 
# those terms.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# file LICENSE for more details.
#
###################################################################

import os
from urlparse import urlparse

from fabric.api import settings

from .database import createdb, dropdb, setup_db_access
from .django import get_django_settings, manage, syncdb
from .environment import bootstrap, virtualenv_local


def run(*args, **kwargs):
    """Run SSO using devserver."""
    if not args:
        parsed = urlparse(get_django_settings('SSO_ROOT_URL')['SSO_ROOT_URL'])
        args = [parsed.netloc]
    manage('runserver', *args, **kwargs)

def test(extra='', coverage=False):
    """Run unit tests."""
    args = ['--noinput', extra]
    manage('test', args)

def apitests():
    """Run API tests only."""
    manage('test', '', 
    	'--testing_test_discover_root=./identityprovider/tests/api')

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

    cmd = ['sst-run']
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

def jenkins():
    """Run the tests for jenkins."""
    bootstrap()
    # use the system's database
    virtualenv_local("sed -i 's/db_host = .*/db_host =/g' django/local.cfg")
    resetdb()
    manage('loaddata test')
    manage('jenkins', '', 
    	'--testing_test_discover_root=')

def resetdb():
    """Drop and recreate then sync the database."""
    with settings(hide='warnings'):
        dropdb(warn_only=True)
    createdb()
    syncdb()
    setup_db_access()

def docs():
	""""Build docs"""
    virtualenv_local('sphinx-build docs docs/html')
    
def _is_true(arg, name):
    if arg.lower() in ('t', 'true', 'on', '1', 'yes'):
        return True
    elif arg.lower() in ('f', 'false', 'off', '0', 'no'):
        return False
    raise ArgumentError(
        "Argument {!r} should be boolean, was {!r}".format(name, arg))
