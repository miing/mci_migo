# -*- coding: utf-8 -*-

# Copyright 2012, 2013 Canonical Ltd.
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License version 3, as 
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranties of
# MERCHANTABILITY, SATISFACTORY QUALITY, or FITNESS FOR A PARTICULAR
# PURPOSE.  See the GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import sys

from fabric.api import env, local


VIRTUALENV = '.env'


def bootstrap():
    setup_virtualenv()
    _install_dependencies()


def setup_virtualenv():
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


def _create_virtualenv():
    if not os.path.exists(VIRTUALENV):
        virtualenv_bin_path = local('which virtualenv', capture=True)
        virtualenv_version = local('{0} {1} --version'.format(
            sys.executable, virtualenv_bin_path), capture=True)
        args = '--distribute --clear'
        if virtualenv_version < '1.7':
            args += ' --no-site-packagaes'
        local('{0} {1} {2} {3}'.format(sys.executable, virtualenv_bin_path,
            args, VIRTUALENV), capture=False)


def _activate_virtualenv():
    activate_this = os.path.abspath(
        '{0}/bin/activate_this.py'.format(env.virtualenv))
    execfile(activate_this, dict(__file__=activate_this))   


def _install_dependencies():
    run_in_virtualenv_local(
        'pip install -U -r requirements.txt', capture=False)


def run_in_virtualenv_local(command, capture=True):
    prefix = ''
    virtual_env = env.get('virtualenv', None)
    if virtual_env:
        prefix = '. {0}/bin/activate && '.format(virtual_env)
    command = prefix + command
    return local(command, capture=capture)
