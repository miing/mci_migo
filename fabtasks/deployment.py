#   -*- coding: utf-8 -*-
"""Fabric commands for deploying from the branches to testing server."""

import os
import shutil
import tempfile

from fabric.api import env, run, local, put, cd, sudo
from fabric.contrib import files


def _format(s):
    """Format string using substitutions from fabric's env."""
    return s.format(**env)


def _run(cmd):
    run(_format(cmd))


def _local(cmd):
    local(_format(cmd))


def _sudo(cmd):
    sudo(_format(cmd))


def apache_graceful():
    sudo('service apache2 graceful', shell=False)


def _check_and_copy_local_cfg(filename):
    configs_path = _format(
        "{deploy_dir}/canonical-identity-provider/branches/project")
    config_path = os.path.join(configs_path, filename)
    local_config_path = os.path.join(configs_path, 'local.cfg')
    if files.exists(config_path):
        if files.exists(local_config_path):
            print "local.cfg file exists on remote server. backing up."
            run("cp %s %s.bak" % (local_config_path, local_config_path))
        run("cp %s %s" % (config_path, local_config_path))
    else:
        print "Cannot find file: %s" % config_path


def deploy(config_branch, deploy_dir="/srv/localhost/staging",
        config_file='', production=False):
    env.cm = "/usr/lib/config-manager/cm.py"

    if not files.exists(env.cm):
        sudo("apt-get install --yes config-manager")

    env.config_branch = config_branch
    env.deploy_dir = deploy_dir
    env.build_dir = tempfile.mkdtemp()
    env.sourcedeps = _format("{build_dir}/cm/configmanager.conf")
    env.revno = local("bzr revno").strip()

    _local("bzr branch {config_branch} {build_dir}/cm")

    _local("sed -i 's/bazaar.isd/bazaar.launchpad.net/g' {sourcedeps}")

    if not production:
        _local("sed -i '1 s/stable/trunk/' {sourcedeps}")
        _local("sed -i 's/;revno=[0-9]\+$//' {sourcedeps}")

    put(env.sourcedeps, deploy_dir)

    with cd(deploy_dir):
        if files.exists("canonical-identity-provider"):
            _sudo("chown -R jenkins: canonical-identity-provider")
            _run("{cm} update configmanager.conf")
        else:
            _run("{cm} build configmanager.conf")

        _run("rm configmanager.conf")

    shutil.rmtree(env.build_dir, ignore_errors=True)

    if config_file:
        _check_and_copy_local_cfg(config_file)

    _sudo("chown -R www-data: {deploy_dir}/canonical-identity-provider")

    apache_graceful()
