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

    def setUp(self):
        super(FailoverTestCase, self).setUp()

        self.original_db = postgresql_base.Database
        postgresql_base.Database = mockdb
        try:
            dsn = settings.TEST_DSN
        except AttributeError:
            print """*** To run the tests you need to provide a TEST_DSN
            setting that will be used throughout the tests, instead
            of your configured DB_CONNECTIONS.
            """
            raise
        mockdb.fixate_connection(dsn)

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
            self.client.get('/')

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
