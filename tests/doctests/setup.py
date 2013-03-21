# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from django.db import connection, transaction
from django.core import management
from django.core.management.color import no_style
from django.core.management.sql import sql_flush


def setUp(doctest):
    sql_list = sql_flush(no_style(), only_django=True)
    # Drop the current db
    cursor = connection.cursor()
    cursor.execute('SHOW statement_timeout')
    statement_timeout = cursor.fetchone()
    cursor.execute('SET statement_timeout TO 0')
    try:
        for sql in sql_list:
            # Tweak the sql so that tables can be dropped
            if sql.startswith('TRUNCATE '):
                sql = sql.strip(';') + ' CASCADE;'
                cursor.execute(sql)
                transaction.commit_unless_managed()
    finally:
        cursor.execute("SET statement_timeout TO '%s'" % statement_timeout)
    # Set up the test fixtures
    management.call_command('loaddata', 'test.json', verbosity=0)
