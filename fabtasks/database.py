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
import textwrap

from fabric.api import env, local, settings
from fabric.context_managers import hide

from .constants import PG_BIN_PATH
from .django import get_django_settings, manage, syncdb


def setup_postgresql_server():
    """Setup the PostgreSQL server."""
    _set_postgres_environment()
    local("mkdir -p %(DATA)s" % env.postgres)
    local("%(ENV)s %(BIN)s/initdb -A trust -D %(DATA)s" % env.postgres)
    config = textwrap.dedent("""
        fsync = off
        standard_conforming_strings = off
        escape_string_warning = off
    """)
    with open("%(DATA)s/postgresql.conf" % env.postgres, 'a') as pg_conf:
        pg_conf.write(config)
    start_database()
    setup_database()

def shutdown_postgresql_server():
    """Shutdown the PostgreSQL server."""
    _set_postgres_environment()
    dropdb()
    stop_database()
    local("rm -rf %s" % env.postgres['HOST'])

def start_database():
    """Start the PostgreSQL server."""
    _set_postgres_environment()
    cmd = ['%(ENV)s', '%(BIN)s/pg_ctl', 'start', '-w', '-l',
        '%(HOST)s/postgresql.log', '-o', '"-F -k %(HOST)s -h \'\'"']
    local(' '.join(cmd) % env.postgres)

def stop_database():
    """Stop the PostgreSQL server."""
    _set_postgres_environment()
    cmd = ['%(ENV)s', '%(BIN)s/pg_ctl', 'stop', '-w', '-m', 'fast']
    local(' '.join(cmd) % env.postgres)

def setup_database():
    """Setup the database."""
    success = _check_database()
    if not success:
        _createrole()
        createdb()
    syncdb()
    setup_db_access()

def createdb():
    """Create the database."""
    _set_postgres_environment()
    local("%(ENV)s %(BIN)s/createdb -U postgres -O postgres %(DATABASE)s" % env.postgres)

def dropdb(warn_only=False):
    """Remove the database."""
    _set_postgres_environment()
    if isinstance(warn_only, basestring):
        warn_only = warn_only.lower() == 'yes'
    with settings(warn_only=warn_only):
        local("%(ENV)s %(BIN)s/dropdb -U postgres %(DATABASE)s" % env.postgres)

def setup_db_access():
    """Grant access to the database."""
    _set_postgres_environment()
    django_settings = get_django_settings('INSTALLED_APPS')
    if 'pgtools' in django_settings['INSTALLED_APPS']:
        manage('grantuser', env.database['USER'],
               '--django_database_user=postgres')

def _set_postgres_environment():
    """Update the environment with the PostgreSQL settings."""
    if 'postgres' in env:
        # environment already set up
        return

    _set_database_environment()

    pg_env = []
    env.postgres = {
        'BIN': PG_BIN_PATH
        'DATABASE': env.database['NAME'],
    }

    host = os.environ.get('PGHOST', env.database['HOST'])
    if host:
        data = "%s/data" % host
        env.postgres['HOST'] = host
        env.postgres['DATA'] = data
        pg_env.append("PGHOST=%s" % host)
        pg_env.append("PGDATA=%s" % data)

    port = env.database['PORT']
    if port:
        pg_env.append("PGPORT=%s" % port)

    env.postgres['ENV'] = ' '.join(pg_env)

def _set_database_environment():
    """Update the environment with the database settings."""
    if 'database' in env:
        # environment already set up
        return

    settings = get_django_settings('DATABASES')
    db = settings['DATABASES']
    env.database = db['default']

def _check_database():
    """Check the database is accessible."""
    with hide('aborts', 'running'):
        try:
            _set_postgres_environment()
            local("%(ENV)s psql -U postgres -c '\q'"
                % env.postgres, capture=False)
            success = True
        except SystemExit:
            # there was an error connecting to the db,
            # presumably the db didn't exist
            success = False
    return success

def _createrole():
    """Create required users/roles."""
    _set_postgres_environment()
    local("%(ENV)s %(BIN)s/createuser --superuser --createdb postgres" % env.postgres)
    user = env.database['USER']
    if user != 'postgres':
        cmd = "%(ENV)s %(BIN)s/createuser -S -d -r %%(USER)s"
        local((cmd % env.postgres) % env.database)
