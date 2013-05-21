# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

import StringIO
import shutil
import sys
import tempfile

from copy import copy

from django.conf import settings
from django.core.handlers.wsgi import WSGIHandler
from django.core.management import call_command, CommandError
from wsgi_intercept import (
    add_wsgi_intercept,
    remove_wsgi_intercept,
    urllib2_intercept,
)

from identityprovider.readonly import ReadOnlyManager
from identityprovider.tests.utils import SSOBaseTestCase


class ReadonlyCommandTestCase(SSOBaseTestCase):

    def setUp(self):
        super(ReadonlyCommandTestCase, self).setUp()

        self.rm = ReadOnlyManager()
        # make sure we're clear everything up before leaving
        self.addCleanup(self.rm.clear_readonly)
        self.addCleanup(self.rm.clear_failed, 'master')

        self._stdout = sys.stdout
        self._stderr = sys.stderr
        sys.stdout = StringIO.StringIO()
        sys.stderr = StringIO.StringIO()
        self.addCleanup(setattr, sys, 'stdout', self._stdout)
        self.addCleanup(setattr, sys, 'stderr', self._stderr)

        self.servers = [
            {'SERVER_ID': 'localhost', 'HOST': 'localhost', 'PORT': '8000'},
            {'SERVER_ID': 'otherhost', 'HOST': 'localhost', 'PORT': '8001'},
        ]
        _APP_SERVERS = settings.APP_SERVERS
        settings.APP_SERVERS = self.servers
        self.addCleanup(setattr, settings, 'APP_SERVERS', _APP_SERVERS)

        _DBFAILOVER_FLAG_DIR = getattr(settings, 'DBFAILOVER_FLAG_DIR', None)
        settings.DBFAILOVER_FLAG_DIR = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, settings.DBFAILOVER_FLAG_DIR, True)
        self.addCleanup(setattr, settings, 'DBFAILOVER_FLAG_DIR',
                        _DBFAILOVER_FLAG_DIR)

        backup_db = copy(settings.DB_CONNECTIONS[0])
        backup_db['ID'] = 'backup'
        settings.DB_CONNECTIONS.append(backup_db)

        # setup wsgi intercept mechanism to simulate wsgi server
        urllib2_intercept.install_opener()
        for server in self.servers:
            add_wsgi_intercept(server['HOST'], int(server['PORT']),
                               WSGIHandler)

    def tearDown(self):
        # remove wsgi intercept mechanism
        for server in self.servers:
            remove_wsgi_intercept(server['HOST'], int(server['PORT']))
        urllib2_intercept.uninstall_opener()

        self.rm.set_db(settings.DB_CONNECTIONS[0])

    def get_status(self):
        call_command('readonly', list_servers=True)
        sys.stdout.seek(0)
        output = sys.stdout.read()
        return output

    def test_readonly(self):
        self.assertRaises(CommandError, call_command, 'readonly')

    def test_readonly_list_all(self):
        output = self.get_status()
        self.assertTrue(self.servers[0]['SERVER_ID'] in output)

    def test_readonly_set(self):
        call_command('readonly', self.servers[0]['SERVER_ID'], action='set')
        self.rm.check_readonly()
        self.assertTrue(settings.READ_ONLY_MODE)

    def test_readonly_clear(self):
        call_command('readonly', self.servers[0]['SERVER_ID'], action='clear')
        self.rm.check_readonly()
        self.assertFalse(settings.READ_ONLY_MODE)

    def test_readonly_enable(self):
        # prepare test
        call_command('readonly', self.servers[0]['SERVER_ID'],
                     action='disable', database='master')
        # perform test
        call_command('readonly', self.servers[0]['SERVER_ID'],
                     action='enable', database='master')
        self.assertFalse(self.rm.is_failed('master'))

    def test_readonly_disable(self):
        call_command('readonly', self.servers[0]['SERVER_ID'],
                     action='disable', database='master')
        self.assertTrue(self.rm.is_failed('master'))

    def test_readonly_set_all(self):
        call_command('readonly', action='set', all_servers=True)
        output = self.get_status()
        for server in settings.APP_SERVERS:
            expected = "%s -- In readonly mode" % server['SERVER_ID']
            self.assertTrue(expected in output)

    def test_readonly_clear_all(self):
        call_command('readonly', self.servers[0], action='clear',
                     all_servers=True)
        output = self.get_status()
        for server in settings.APP_SERVERS:
            expected = "%s -- Operating normally" % server['SERVER_ID']
            self.assertTrue(expected in output)

    def test_readonly_enable_all(self):
        call_command('readonly', action='enable', database='master',
                     all_servers=True)
        output = self.get_status()
        self.assertEqual(len(settings.APP_SERVERS),
                         output.count('master:  OK'))

    def test_readonly_disable_all(self):
        call_command('readonly', self.servers[0], action='disable',
                     database='master', all_servers=True)
        output = self.get_status()
        self.assertEqual(len(settings.APP_SERVERS),
                         output.count('master:  Failed'))
