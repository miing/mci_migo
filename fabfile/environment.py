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
	SPKG,
	IPKG,
	RPKG,
	EIPIP,
	IPIP,
	BASE_DEPENDENCIES,
	PSYCOPG2_CONFLICTS,
	BASE_REMOVED_DEPENDENCIES,
	BASE_PYPI_DEPENDENCIES,
	VIRTUALENV,
)


def bootstrap(download_cache_path=None):
    """Bootstrap the development environment"""
    setup_baseenv()
    setup_virtualenv()
    install_dependencies(download_cache_path)
    setup_configuration()


def clean():
    """Clean up compiled and backup files"""
    with lcd('dj'):
        local("rm -rf .coverage coverage.d coverage.xml")
    local("find . -name '*.~*' -delete")
    local("find . -name '*.pyc' -delete")


def setup_baseenv():
	"""Setup base env"""
	_install_base_dependencies(_check_base_dependencies())
	_check_psycopg2_conflicts()
	_pip_base_dependencies()


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
	_work_around()


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
	"""Check base dependencies"""
	uninstalled = []
	for pkg in BASE_DEPENDENCIES:
		output = local(LPKG % pkg, capture=True).strip()
		if output != '1':
			uninstalled.append(pkg)

	nonexistent = []
	for pkg in uninstalled:
		output = local(SPKG % (pkg, pkg), capture=True).strip()
		if output != '1':
			nonexistent.append(pkg)
    
	if nonexistent:
		print "Please try to install the following packages, as they are required"
		print "in order to build some of the dependencies:"
		for pkg in nonexistent:
			print pkg
			sys.exit(1)
	return uninstalled


def _install_base_dependencies(packages):
	"""Install base dependencies"""
	for pkg in packages:
		local(IPKG % pkg)


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


def _pip_base_dependencies():
	"""Install PYPI base dependencies"""
	for pkg in BASE_REMOVED_DEPENDENCIES:
		output = local(LPKG % pkg, capture=True).strip()
		if output == '1':
			local(RPKG % pkg)
	
	for pkg in BASE_PYPI_DEPENDENCIES:
		if pkg == 'pip':
			local(EIPIP % pkg)
		else:
			local(IPIP % pkg)


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


def _work_around():
	"""Patch installed dependencies"""
	_pypi_paste_no_init_file()
	_pypi_django_piston_no_init_file()
	

def _pypi_paste_no_init_file():
	"""Fix 'No module named paste.request'
	
	For the sake of missing __init__.py under paste dir,
	the issue still exists in recent version of Paste (1.7.5.1).
	"""
	dest_path='lib/python%d.%d/site-packages/paste' % sys.version_info[:2]
	dest_file='__init__.py'
	if not os.path.exists('%s/%s/%s' % (VIRTUALENV, dest_path, dest_file)):
		virtualenv_local('pip install --download=. paste')
		virtualenv_local('tar xzvf Paste*.tar.gz')
		virtualenv_local('cp Paste*/paste/__init__.py %s/%s' % (VIRTUALENV, dest_path))
		virtualenv_local('rm -rf Paste*')


def _pypi_django_piston_no_init_file():
	"""Fix 'No module named piston.authentication'
	
	For the sake of missing __init__.py under paste dir,
	the issue still exists in recent version of django-piston (0.2.3).
	"""
	dest_path='lib/python%d.%d/site-packages/piston' % sys.version_info[:2]
	dest_file='__init__.py'
	if not os.path.exists('%s/%s/%s' % (VIRTUALENV, dest_path, dest_file)):
		virtualenv_local('pip install --download=. django-piston')
		virtualenv_local('tar xzvf django-piston*.tar.gz')
		virtualenv_local('cp dj*-piston*/piston/__init__.py %s/%s' % (VIRTUALENV, dest_path))
		virtualenv_local('rm -rf django-piston*')


def _create_local_cfg():
	"""Create base local configuration file"""
	config = textwrap.dedent("""
        [__noschema__]
        basedir = %s

        [__main__]
        includes = config/devel.cfg
        test_dsn = host=%(db_host)s dbname=%(db_name)s user=%(db_user)s
    """ % (os.path.abspath(os.curdir), env.virtualenv))
	
	with file('dj/local.cfg', 'w') as local_cfg: 
		local_cfg.write(config)
