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
import shutil
import tempfile

from fabric.api import *
from fabric.contrib import files


def deploy(config_branch, deploy_dir="/srv/localhost/staging",
		config_file='', production=False):
	"""Deploy target site to remote host"""
	env.config_branch = config_branch
	env.deploy_dir = deploy_dir
	env.build_dir = tempfile.mkdtemp()
	env.sourcedeps = _format("{build_dir}/cm/configmanager.conf")
	env.revno = local("bzr revno").strip()
	
	put(env.sourcedeps, deploy_dir)
	
	with cd(deploy_dir): 
		if files.exists("migo"): 
			_sudo("chown -R jenkins: migo")
			_run("{cm} update configmanager.conf") 
		else: 
			_run("{cm} build configmanager.conf")

        _run("rm configmanager.conf") 
       
	shutil.rmtree(env.build_dir, ignore_errors=True)
	
	if config_file: 
		_check_and_copy_local_cfg(config_file) 
	
	_sudo("chown -R www-data: {deploy_dir}/migo")
	apache_restart()

def apache_restart():
	"""Restart Apache on remote host"""
	sudo('/etc/init.d/apache2 restart', shell=False)

def apache_reload():
	"""Reload Apache on remote host"""
	sudo('/etc/init.d/apache2 reload', shell=False)

def _check_and_copy_local_cfg(filename):
    configs_path = _format("{deploy_dir}/migo")
    config_path = os.path.join(configs_path, filename)
    local_config_path = os.path.join(configs_path, 'local.cfg')
    if files.exists(config_path):
        if files.exists(local_config_path):
            print "local.cfg file exists on remote server. backing up."
            run("cp %s %s.bak" % (local_config_path, local_config_path))
        run("cp %s %s" % (config_path, local_config_path))
    else:
        print "Cannot find file: %s" % config_path

def _run(cmd):
    run(_format(cmd))

def _local(cmd):
    local(_format(cmd))

def _sudo(cmd):
    sudo(_format(cmd))
    
def _format(s):
    """Format string using substitutions from fabric's env"""
    return s.format(**env)
