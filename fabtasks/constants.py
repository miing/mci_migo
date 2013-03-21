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

import platform

PG_VERSION = '9.1'
SYSTEM_NAME = platform.system()
if SYSTEM_NAME == 'Linux':
	# Linux based platforms
	DISTRO_NAME = (platform.linux_distribution())[0]
	if DISTRO_NAME in ('Debian', 'Ubuntu'):
		# Debian based distros
		LPKG = "dpkg -l %s 2> /dev/null | grep '^ii' | wc -l"
		IPKG = "apt-get -y install %s"
		BASE_DEPENDENCIES = [
			# For grabing source code or files
			'git-core',
			'wget',
			# For building pypi packages
			'build-essential',
			# For web server
			'apache2',
			'libapache2-mod-wsgi',
			# For database engine
			"postgresql-%s" % PG_VERSION,
			'libpq-dev',
			"postgresql-plpython-%s" % PG_VERSION,
			# For python environment
			'python',
			'python-dev',
			'python-setuptools',
			#'python-virtualenv',
			#'python-pip'
			'swig',
			# For performance
			'memcached',
			# For debugging
			'python-profiler',
			# For testting
			'libxml2-dev',
			'libxslt1-dev',
			'xvfb'
		]
		PSYCOPG2_CONFLICTS = ['python-egenix-mx-base-dev']
		PG_BIN_PATH = "/usr/lib/postgresql/%s/bin" % PG_VERSION,
	elif DISTRO_NAME in ('SuSE', 'Fedora', 'Centos', 'Redhat'):
		# RPM based distros
		LPKG = None
		IPKG = None
		BASE_DEPENDENCIES = None
		PSYCOPG2_CONFLICTS = None
		PG_BIN_PATH = None
	else:
		# Not supported distros
		LPKG = None
		IPKG = None
		BASE_DEPENDENCIES = None
		PSYCOPG2_CONFLICTS = None
		PG_BIN_PATH = None
elif SYSTEM_NAME == 'MacOS':
	# MacOS platforms
	LPKG = None
	IPKG = None
	BASE_DEPENDENCIES = None
	PSYCOPG2_CONFLICTS = None
	PG_BIN_PATH = None
elif SYSTEM_NAME == 'Windows':
	# Windows platforms
	LPKG = None
	IPKG = None
	BASE_DEPENDENCIES = None
	PSYCOPG2_CONFLICTS = None
	PG_BIN_PATH = None
else:
	# Unknown platforms
	LPKG = None
	IPKG = None
	BASE_DEPENDENCIES = None
	PSYCOPG2_CONFLICTS = None
	PG_BIN_PATH = None
	
VIRTUALENV = '.env'

APPS = [
    "api",
    "identityprovider",
    "webui",
]
