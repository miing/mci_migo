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

from __future__ import absolute_import
import json
import os
import sys

from fabric.context_managers import lcd

from .constants import APPS
from .environment import virtualenv_local


def get_django_settings(*keys):
    # setup the correct django environment
    sys.path.insert(0, os.path.abspath(os.curdir))
    os.environ['DJANGO_SETTINGS_MODULE'] = 'django.settings'
    # get django settings
    from django.conf import settings

    result = dict.fromkeys(keys)
    for key in keys:
        result[key] = getattr(settings, key)

    return result


def brand(brand):
    s = get_django_settings('TEMPLATE_DIRS', 'BRAND')
    template_dirs = s['TEMPLATE_DIRS']
    current_brand = s['BRAND']

    def update_dir(d):
        path, _, dirname = d.rpartition('/')
        if dirname == current_brand:
            return '/'.join([path, brand])
        return d

    template_dirs = map(update_dir, template_dirs)

    os.environ["CONFIGGLUE_DJANGO_TEMPLATE_DIRS"] = json.dumps(template_dirs)

    os.environ["CONFIGGLUE_BRANDING_BRAND"] = brand
    os.environ["CONFIGGLUE_BRANDING_BRAND_TEMPLATE_DIR"] = brand


def manage(command, *args, **kwargs):
    """Run manage.py command"""
    cmd = [
        "python django/manage.py",
        command,
    ]
    args += tuple("%s=%s" % (k,v) for (k,v) in kwargs.items())
    cmd.extend(args)

    virtualenv_local(" ".join(cmd), capture=False)


def compilemessages(args=''):
    """Compile .po translation files into binary (.mo)."""
    cmd = 'python ../django/manage.py compilemessages'
    if args:
        cmd += " %s" % args
    for app in APPS:
        with lcd(app):
            virtualenv_local(cmd, capture=False)

def makemessages():
    """Create/Update translation strings in .po files."""
    django_settings = get_django_settings('SUPPORTED_LANGUAGES')
    supported_languages = django_settings['SUPPORTED_LANGUAGES']
    for app in APPS:
        for lang in supported_languages:
            with lcd(app):
                cmd = ("python ../django/manage.py makemessages "
                    "-l {0} -e .html,.txt")
                if '-' in lang:
                    language, country = lang.split('-')
                    locale_name = "{0}_{1}".format(language, country.upper())
                else:
                    locale_name = lang
                virtualenv_local(cmd.format(locale_name), capture=False)

def loaddata():
    pass

def syncdb():
    """Sync the database.

    If south is listed in INSTALLED_APPS syncdb runs with --migrate.
    """
    args = ['--noinput', '--django_database_user=postgres',
        '--django_database_password=']
    django_settings = get_django_settings('INSTALLED_APPS')
    if 'south' in django_settings['INSTALLED_APPS']:
        args.append('--migrate')
    manage('syncdb', *args)
