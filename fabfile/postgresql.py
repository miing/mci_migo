###################################################################
#
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

from fabric.api import env, cd, local, settings
from fabric.context_managers import hide

from .constants import PG_BIN_PATH
from .django import get_django_settings


def pgsql_createuser(user=None, password=None, superuser=True, createdb=True,
                	 createrole=True, inherit=True, login=True,
                	 connection_limit=None, encrypted_password=False):
	"""Create a PostgreSQL user if not existing yet"""
	_pgsql_gets_ready()
    
	user = user if user else env.postgres['USER']
	if _pgsql_user_exists(user):
		print "** User '%s' in postgresql already exists there" % user
		return

	options = '%s ' % user
	password = password if password else env.postgres['PASSWORD']
	if password:
		password_type = 'ENCRYPTED' if encrypted_password else 'UNENCRYPTED'
		password = "%s PASSWORD '%s' " % (password_type, password)
		options += password
	superuser = 'SUPERUSER ' if superuser else 'NOSUPERUSER '
	options += superuser
	createdb = 'CREATEDB ' if createdb else 'NOCREATEDB '
	options += createdb
	createrole = 'CREATEROLE ' if createrole else 'NOCREATEROLE '
	options += createrole
	inherit = 'INHERIT ' if inherit else 'NOINHERIT '
	options += inherit
	login = 'LOGIN ' if login else 'NOLOGIN '
	options += login
	if connection_limit is not None:
		connection_limit = 'CONNECTION LIMIT %d ' % connection_limit
		options += connection_limit
	_run_as_pg('''psql -c "CREATE USER %s;"''' % options.strip())


def pgsql_dropuser(user=None):
	"""Cancel a PostgreSQL user if existing"""
	_pgsql_gets_ready()
	
	user = user if user else env.postgres['USER']
	if not _pgsql_user_exists(user):
		print "** User '%s' in postgresql never exists there" % user
		return
	_run_as_pg('''psql -c "DROP USER %s;"''' % user)


def pgsql_createdb(name=None, user=None, template='template0', encoding='UTF8',
                   locale='en_US.utf8'):
	"""Create a PostgreSQL database if not existing yet"""
	_pgsql_gets_ready()
    
	user = user if user else env.postgres['USER']
	if not _pgsql_user_exists(user):
		print "** User '%s' in postgresql never exists there" % user
		return
	name = name if name else env.postgres['NAME']
	if _pgsql_database_exists(name):
		print "** Database '%s' for user '%s' in postgresql already exists there" \
				% (name, user)
		return

	options = '--owner=%s ' % user
	options += '--template=%s ' % template
	options += '--encoding=%s ' % encoding
	options += '--lc-collate=%s ' % locale
	options += '--lc-ctype=%s ' % locale
	options += '%s' % name
	_run_as_pg("createdb %s" % options.strip())


def pgsql_dropdb(name=None):
	"""Remove a PostgreSQL database if existing"""
	_pgsql_gets_ready()
	
	name = name if name else env.postgres['NAME']
	if not _pgsql_database_exists(name):
		print "** Database '%s' in postgresql never exists there" % name
		return
	_run_as_pg("dropdb %s" % name)
	

def _pgsql_gets_ready():
	"""Check if a PostgreSQL server is ready"""
	_pgsql_is_installed()
	_pgsql_sets_environment()
	_pgsql_is_running()
	

def _pgsql_user_exists(user):
	"""Check if a PostgreSQL user exists"""
	with hide('running', 'stdout', 'stderr', 'warnings'):
		cmd = '''psql -t -A -c "SELECT COUNT(*) FROM pg_user WHERE usename = '%s';"'''
		res = _run_as_pg(cmd % user, capture=True)
	return (res == "1")


def _pgsql_database_exists(name):
	"""Check if a PostgreSQL database exists"""
	with hide('aborts', 'running', 'stdout', 'stderr', 'warnings'):
		try:
			cmd = '''psql -d %s -c "\q"'''
			_run_as_pg(cmd % name, capture=False)
			succecced = True
		except SystemExit:
			succecced = False
	return succecced


def _run_as_pg(command, capture=True):
	"""Run command as 'postgres' user"""
	prefix = "sudo -u postgres "
	command = prefix + command
	return local(command, capture=capture).strip()


def _pgsql_is_installed():
	"""Check if postgresql is installed"""
	with hide('aborts', 'stdout', 'stderr', 'running'):
		try:
			local("which psql", capture=False)
		except SystemExit:
			# Here arrive we if pgsql is not yet installed
			# on your system
			print "** PostgrSQL not installed"
			sys.exit(1)
	

def _pgsql_is_running():
	"""Check if a PostgreSQL server is running"""
	with hide('aborts', 'stdout', 'stderr', 'running'):
		try:
			_run_as_pg("psql -c '\q'", capture=False)
		except SystemExit:
            # Here arrive we if pgsql server is not yet running,
            # when trying connecting to the default database for 
            # the default user
			print "** PostgreSQL Server not up and running."
			sys.exit(1)


def _pgsql_sets_environment():
	"""Setup environment with PostgreSQL settings"""
	if 'postgres' in env:
        # environment already set up
		return
	
	settings = get_django_settings('DATABASES')
	db = settings['DATABASES']
	database = db['default']
    
	pg_env = []
	env.postgres = {
        'BIN': "%s" % PG_BIN_PATH,
        'NAME': database['NAME'],
        'USER': database['USER'],
        'PASSWORD': database['PASSWORD'],
	}

	host = database['HOST']
	if host:
		env.hosts = ['%s' % host]
		env.postgres['HOST'] = host
		pg_env.append("PGHOST=%s" % host)

	port = database['PORT']
	if port:
		env.postgres['PORT'] = port
		pg_env.append("PGPORT=%s" % port)

	env.postgres['ENV'] = ' '.join(pg_env)
