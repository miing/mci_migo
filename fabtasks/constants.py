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

APPS = [
    "api",
    "identityprovider",
    "webui",
]
PG_VERSION = '9.1'
BUILD_DEPENDENCIES = [
    'libpq-dev',
    'libxml2-dev',
    'libxslt1-dev',
    'memcached',
    "postgresql-plpython-%s" % PG_VERSION,
    'python-dev',
    'python-m2crypto',
    'swig',
]
PSYCOPG2_CONFLICTS = ['python-egenix-mx-base-dev']
VIRTUALENV = '.env'

try:
    import cProfile
except ImportError:
    BUILD_DEPENDENCIES.append('python-profiler')
