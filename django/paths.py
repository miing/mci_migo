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

import sys
import os
import os.path

PATHS = [
    # base and django config
    '.',
    'django',
    # dependencies
    '.env/lib/python%d.%d/site-packages' % sys.version_info[:2],
]

# when deployed via cfgmgr, this file (paths.py) should be located in
# <base>/branches/project
curdir = os.path.abspath(os.path.dirname(__file__))
base = os.path.abspath(os.path.join(curdir, '..'))


def get_paths(paths):
    """Sets up necessary python paths for Pay in prod/staging"""
    # only include a path if not already in sys.path to avoid duplication of
    # paths when using code reloading
    path_set = set(sys.path)
    for p in paths:
        path = os.path.join(base, p)
        if path not in path_set:
            yield path


def setup_paths():
    sys.path = list(get_paths(PATHS)) + sys.path
    os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'


if __name__ == '__main__':
    # For use in shell scripting
    # e.g. $(python paths.py)
    print "export PYTHONPATH=%s" % ":".join(get_paths(PATHS))
    print "export DJANGO_SETTINGS_MODULE=settings"
