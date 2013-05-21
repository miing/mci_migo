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


PATHS = [
    # base and django config
    '.',
    'dj',
    # dependencies
    '.env/lib/python%d.%d/site-packages' % sys.version_info[:2],
]

curdir = os.path.dirname(os.path.realpath(__file__))
base = os.path.realpath(os.path.join(curdir, '..'))


def setup_paths():
	"""Setup necessary python paths"""
	sys.path = list(_get_paths(PATHS)) + sys.path
	os.environ['DJANGO_SETTINGS_MODULE'] = 'dj.settings'


def _get_paths(paths):
    """Get a set of paths not duplicate"""
    # only include a path if not already in sys.path to avoid duplication of
    # paths when using code reloading
    path_set = set(sys.path)
    for p in paths:
        path = os.path.join(base, p)
        if path not in path_set:
            yield path


if __name__ == '__main__':
    # For use in shell scripting
    # e.g. $(python paths.py)
    print "export PYTHONPATH=%s" % ":".join(_get_paths(PATHS))
    print "export DJANGO_SETTINGS_MODULE=dj.settings"
