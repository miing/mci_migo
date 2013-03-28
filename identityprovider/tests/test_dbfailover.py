# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

import tempfile
import os
import shutil

from django.db.backends.postgresql_psycopg2 import base as postgresql_base
from django.conf import settings
from django.db import DEFAULT_DB_ALIAS, connection
from mock import patch

from identityprovider.tests import mockdb
from identityprovider.readonly import ReadOnlyManager

from identityprovider.tests.utils import SSOBaseTestCase, skipOnSqlite


@skipOnSqlite
class FailoverTestCase(SSOBaseTestCase):

    @classmethod
    def setUpClass(self):
        """Get the current connection params for the non-test database."""
        # Maintaining the behaviour of the previous TEST_DSN setting
        # which was set in the local.cfg as:
        # test_dsn = host=%(db_host)s dbname=%(db_name)s user=%(db_user)s
        # (ie. the normal database connection).
        # It would be nice if this was in a re-usable fn, but as it is,
        # it's taken directly from django.db.backends.postgresql_psycopg2.
        # base.DatabaseWrapper._cursor. We setup once for the test case
        # because the settings_dict is updated during the tests.
        settings_dict = connection.settings_dict
        conn_params = {
            'database': settings_dict['NAME'].replace('test_', ''),
        }

        conn_params.update(settings_dict['OPTIONS'])
        if 'autocommit' in conn_params:
            del conn_params['autocommit']
        if settings_dict['USER']:
            conn_params['user'] = settings_dict['USER']
        if settings_dict['PASSWORD']:
            conn_params['password'] = settings_dict['PASSWORD']
        if settings_dict['HOST']:
            conn_params['host'] = settings_dict['HOST']
        if settings_dict['PORT']:
            conn_params['port'] = settings_dict['PORT']
        self.conn_params = conn_params

    def setUp(self):
        super(FailoverTestCase, self).setUp()

        self.original_db = postgresql_base.Database
        postgresql_base.Database = mockdb
        mockdb.fixate_connection(self.conn_params)

        db = settings.DATABASES[DEFAULT_DB_ALIAS]
        self.test_db_connections = [
            {
                'ID': 'testmaster',
                'NAME': db['NAME'],
                'USER': db['USER'],
                'PASSWORD': db['PASSWORD'],
                'HOST': db['HOST'],
                'PORT': 5432,
            },
            {
                'ID': 'testslave',
                'NAME': db['NAME'],
                'USER': db['USER'],
                'PASSWORD': db['PASSWORD'],
                'HOST': db['HOST'],
                'PORT': 5433
            }]

        self.rm = ReadOnlyManager()
        connection.connection = None

    def tearDown(self):
        self.rm.clear_readonly()
        for db in self.rm.connections:
            self.rm.clear_failed(db['ID'])
        mockdb.fail_next_N_connections(0)
        postgresql_base.Database = self.original_db
        mockdb.release_connection()

    def test_retries(self):
        """ Check that we attempt to connect N times """
        with patch.multiple(settings, DBFAILOVER_ATTEMPTS=3):
            mockdb.fail_next_N_connections(2)
            response = self.client.get('/')

        self.assertEqual(200, response.status_code)

    def test_master_fail(self):
        """Check that we switch to readonly when the master fails."""
        with patch.multiple(settings,
                            DBFAILOVER_ATTEMPTS=3,
                            DB_CONNECTIONS=self.test_db_connections):
            mockdb.fail_next_N_connections(4)
            self.client.get('/')
            self.assertTrue(settings.READ_ONLY_MODE)
            self.assertEqual('testslave',
                             settings.DATABASES[DEFAULT_DB_ALIAS]['ID'])
            self.rm.clear_readonly()
            self.rm.clear_failed('testmaster')
            self.assertFalse(settings.READ_ONLY_MODE)

    def test_complete_fail(self):
        """Check that a friendly oops screen is presented when all connections
           fail, instead of a plain backtrace."""
        with patch.multiple(settings,
                            DBFAILOVER_ATTEMPTS=3,
                            DB_CONNECTIONS=self.test_db_connections):
            mockdb.fail_next_N_connections(6)
            response = self.client.get('/')
            apology = (u"Sorry, something just went wrong in %s." %
                       settings.BRAND_DESCRIPTION)
            self.assertContains(response, apology, status_code=500)

    def test_files_are_in_the_right_place(self):
        """Check that flag files are created in DBFAILOVER_FLAG_DIR."""
        flagdir = tempfile.mkdtemp(dir='/tmp')
        # make sure to remove the temporary folder at the end of the test
        self.addCleanup(shutil.rmtree, flagdir, ignore_errors=True)

        def mock_ping(self):
            # only return a successful ping to the slave db
            return self.current_dbid() == 'testslave'

        with patch.multiple(settings,
                            DBFAILOVER_FLAG_DIR=flagdir,
                            DB_CONNECTIONS=self.test_db_connections,
                            DBFAILOVER_ATTEMPTS=3):
            mockdb.fail_next_N_connections(4)
            target = ('identityprovider.readonly.ReadOnlyManager'
                      '.ping_current_connection')
            with patch(target, mock_ping):
                self.client.get('/')
            flags = os.listdir(flagdir)
            self.assertEqual(len(flags), 2)
