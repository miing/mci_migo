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
import sys
import tempfile
import textwrap

from fabric.api import env, local
from fabric.context_managers import lcd

from .constants import (
	LPKG,
	IPKG,
	BASE_DEPENDENCIES,
	PSYCOPG2_CONFLICTS,
	VIRTUALENV,
)


def bootstrap(download_cache_path=None):
    """Bootstrap the development environment"""
    check_bootstrap_dependencies()

    setup_virtualenv()

    install_dependencies(download_cache_path)
    setup_configuration()

def clean():
    """Clean up compiled and backup files"""
    with lcd('dj'):
        local("rm -rf .coverage coverage.d coverage.xml")
    local("find . -name '*.~*' -delete")
    local("find . -name '*.pyc' -delete")
    
def check_bootstrap_dependencies():
    """Check dependencies required for bootstrap"""
    _check_base_dependencies()
    _check_psycopg2_conflicts()

def setup_virtualenv():
    """Create the virtualenv"""
    created = False
    virtual_env = os.environ.get('VIRTUAL_ENV', None)
    if virtual_env is None:
        if not os.path.exists(VIRTUALENV):
            _create_virtualenv()
            created = True
        virtual_env = VIRTUALENV
    env.virtualenv = os.path.abspath(virtual_env)
    _activate_virtualenv()
    return created

def install_dependencies(download_cache_path=None):
    """Install all dependencies into the virtualenv"""
    _install_pip_dependencies(download_cache_path)

def setup_configuration():
    """Setup the base local configuration file"""
    if not os.path.exists('dj/local.cfg'):
        _create_local_cfg()

def virtualenv_local(command, capture=True):
    """Run a command inside the virtualenv"""
    prefix = ''
    virtual_env = env.get('virtualenv', None)
    if virtual_env:
        prefix = ". %s/bin/activate && " % virtual_env
    command = prefix + command
    return local(command, capture=capture)
    
def _check_base_dependencies():
    """Check base dependencies required for bootstrap"""
    required = []
    for pkg in BASE_DEPENDENCIES:
        output = local(LPKG % pkg, capture=True).strip()
        if output != '1':
            required.append(pkg)
    if required:
        print "Please install the following packages, as they are required"
        print "in order to build some of the dependencies:"
        for pkg in required:
            print pkg
        sys.exit(1)

def _check_psycopg2_conflicts():
    """Check for libraries conflicting with psycopg2"""
    conflicting = []
    for pkg in PSYCOPG2_CONFLICTS:
        output = local(LPKG % pkg, capture=True).strip()
        if output != '0':
            conflicting.append(pkg)
    if conflicting:
        print "Please remove the following packages, as their presence will"
        print "produce the psycopg2 library to be built incorrectly:"
        for pkg in conflicting:
            print pkg
        sys.exit(1)

def _create_virtualenv(clear=False):
    """Create the virtualenv"""
    if not os.path.exists(VIRTUALENV) or clear:
        virtualenv_bin_path = local('which virtualenv', capture=True)
        virtualenv_version = local("%s %s --version" % (
            sys.executable, virtualenv_bin_path), capture=True)
        args = '--distribute --clear'
        if virtualenv_version < '1.7':
            args += ' --no-site-packages'
        local("%s %s %s %s" % (sys.executable,
            virtualenv_bin_path, args, VIRTUALENV), capture=False)

def _activate_virtualenv():
    """Activate the virtualenv"""
    activate_this = os.path.abspath(
        "%s/bin/activate_this.py" % env.virtualenv)
    execfile(activate_this, dict(__file__=activate_this))

def _install_pip_dependencies(download_cache_path=None):
	"""Install all dependencies on pypi or local into the virtualenv"""
	if download_cache_path: 
		cwd = os.getcwd()
		with lcd(download_cache_path): 
			virtualenv_local(
                'make install PACKAGES="-r %s/requirements.txt"' %
                cwd, capture=False) 
	else: 
		virtualenv_local('pip install -r requirements.txt', capture=False)

def _create_local_cfg():
	"""Create base local configuration file"""
	config = textwrap.dedent("""
        [__noschema__]
        basedir = %s
        db_host = %s/db

        [__main__]
        includes = config/devel.cfg
    """ % (os.path.abspath(os.curdir), env.virtualenv))
	config += "test_dsn = host=%(db_host)s dbname=%(db_name)s user=%(db_user)s"
	
	with file('dj/local.cfg', 'w') as local_cfg: 
		local_cfg.write(config)
