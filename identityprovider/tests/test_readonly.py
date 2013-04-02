# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

import copy
import os
import stat
import shutil
import tempfile
import socket
import urllib2

from StringIO import StringIO

from django.conf import settings
from django.contrib.auth.models import User
from django.core.urlresolvers import reverse
from django.db import DEFAULT_DB_ALIAS, connection
from django.utils import simplejson as json
from mock import Mock, patch

from identityprovider.readonly import ReadOnlyManager
from identityprovider import models
from identityprovider.backend.base import DatabaseError
from identityprovider.readonly import (
    _remote_req,
    get_server_atts,
    update_server,
)
from identityprovider.tests.utils import (
    SSOBaseTestCase,
    patch_settings,
    skipOnSqlite,
)


class ReadOnlyBaseTestCase(SSOBaseTestCase):
    """A base TestCase for backing up and restoring our readonly settings"""

    def setUp(self):
        super(ReadOnlyBaseTestCase, self).setUp()
        # XXX, 2013-03-29, nessita: Do not remove this patching since the
        # READ_ONLY_MODE is tweak in tests, and it should be guaranteed the
        # readonlymode stays False
        p = patch_settings(READ_ONLY_MODE=False)
        p.start()
        self.addCleanup(p.stop)

        mock_readonly_secret = 'testsecret'
        db = settings.DATABASES[DEFAULT_DB_ALIAS]
        settings.DB_CONNECTIONS = [{
            'ID': 'master',
            'HOST': db['HOST'],
            'NAME': db['NAME'],
            'USER': db['USER'],
            'PORT': db['PORT'],
            'PASSWORD': db['PASSWORD'],
        }, {
            'ID': 'slave',
            'HOST': db['HOST'],
            'NAME': db['NAME'],
            'USER': db['USER'],
            'PORT': db['PORT'],
            'PASSWORD': db['PASSWORD'],
        }]
        mock_databases = copy.deepcopy(settings.DATABASES)
        mock_dbfailover_flag_dir = tempfile.mkdtemp()
        patched = patch.multiple(settings,
                                 READONLY_SECRET=mock_readonly_secret,
                                 DATABASES=mock_databases,
                                 DBFAILOVER_FLAG_DIR=mock_dbfailover_flag_dir)
        patched.start()
        self.addCleanup(shutil.rmtree, settings.DBFAILOVER_FLAG_DIR, True)
        self.addCleanup(patched.stop)

        mock_settings_dict = copy.deepcopy(connection.settings_dict)
        patched = patch.object(connection, 'settings_dict',
                               mock_settings_dict)
        patched.start()
        self.addCleanup(patched.stop)

        self.rm = ReadOnlyManager()


class ReadOnlyEnabledTestCase(ReadOnlyBaseTestCase):

    def setUp(self):
        super(ReadOnlyEnabledTestCase, self).setUp()
        self.person = self.factory.make_person()

        self.rm.set_readonly()
        self.addCleanup(self.rm.clear_readonly)

        db = settings.DATABASES[DEFAULT_DB_ALIAS].copy()
        # queue cleanup task so DATABASES settings are properly restored
        self.addCleanup(settings.DATABASES.__setitem__, DEFAULT_DB_ALIAS, db)

    @skipOnSqlite
    def test_invalid_insert(self):
        tests = [
            (models.OpenIDRPConfig,
             {'trust_root': 'foo', 'displayname': 'foo', 'description': 'fa'}),
            (models.Person, {'displayname': 'foo', 'name': 'foo'}),
            (models.EmailAddress, {'email': 'foo', 'status': 0}),
        ]
        for cls, args in tests:
            self.assertRaises(DatabaseError,
                              cls.objects.create, **args)

    @skipOnSqlite
    def test_invalid_update(self):
        self.person.displayname = 'Something Different'
        self.assertRaises(DatabaseError, self.person.save)

    def test_current_dbid_with_settings(self):
        settings.DATABASES[DEFAULT_DB_ALIAS]['ID'] = 'mydb'

        self.assertEqual(self.rm.current_dbid(), 'mydb')

    def test_current_dbid_without_settings(self):
        settings.DATABASES[DEFAULT_DB_ALIAS].pop('ID', None)

        self.assertTrue(len(self.rm.connections) > 0)
        self.assertEqual(self.rm.current_dbid(),
                         self.rm.connections[0]['ID'])

    def test_new_account_is_rendered_using_read_only_template(self):
        with patch_settings(READ_ONLY_MODE=True):
            r = self.client.get(reverse('new_account'))
            self.assertTemplateUsed(r, 'readonly.html')


class RemoteRequestTestCase(SSOBaseTestCase):
    msg = 'hello'
    host = 'myhost'
    scheme = 'https'
    vhost = 'http://foobar.baz'

    def setup_mock_urlopen(self, func):
        self.orig_urlopen = urllib2.urlopen
        urllib2.urlopen = func

    def restore_orig_urlopen(self):
        urllib2.urlopen = self.orig_urlopen

    def mock_urlopen(self, req, data=None):
        self.req = req
        self.assertEqual(5, socket.getdefaulttimeout())
        return StringIO(self.msg)

    def test_plain_remote_req(self):
        self.setup_mock_urlopen(self.mock_urlopen)
        server = {'host': self.host}
        self.assertEqual(self.msg, _remote_req(**server))
        self.assertEqual(self.host, self.req.get_host())
        self.restore_orig_urlopen()

    def test_https_remote_req(self):
        self.setup_mock_urlopen(self.mock_urlopen)
        server = {'host': self.host, 'scheme': self.scheme}
        self.assertEqual(self.msg, _remote_req(**server))
        self.assertEqual(self.scheme, self.req.get_type())
        self.assertEqual(self.host, self.req.get_host())
        self.restore_orig_urlopen()

    def test_vhost_remote_req(self):
        self.setup_mock_urlopen(self.mock_urlopen)
        server = {
            'host': self.host,
            'scheme': self.scheme,
            'virtual_host': self.vhost,
        }
        self.assertEqual(self.msg, _remote_req(**server))
        headers = {'Host': self.vhost}
        self.assertEqual(headers, self.req.headers)
        self.assertEqual(self.scheme, self.req.get_type())
        self.assertEqual(self.host, self.req.get_host())
        self.restore_orig_urlopen()

    def test_remote_req_urllib2_error(self):
        def mock_urlopen(req, data=None):
            raise urllib2.URLError((-1, 'error'))

        self.setup_mock_urlopen(mock_urlopen)
        server = {'host': self.host}
        self.assertEqual(None, _remote_req(**server))
        self.restore_orig_urlopen()


class ReadOnlyManagerTestCase(ReadOnlyBaseTestCase):

    def test_set_db(self):
        db = {
            'ID': 'foo',
            'HOST': 'foo_host',
            'PORT': 'foo_port',
            'NAME': 'foo_name',
            'USER': 'foo_user',
            'PASSWORD': 'foo_password',
        }
        self.rm.set_db(db)

        db = settings.DATABASES[DEFAULT_DB_ALIAS]
        for name, value in db.items():
            self.assertEqual(db[name], value)
            self.assertEqual(connection.settings_dict[name], value)


class ReadOnlyRecoveryTestCase(ReadOnlyBaseTestCase):

    def setUp(self):
        super(ReadOnlyRecoveryTestCase, self).setUp()

        self.rm.set_readonly(automatic=True)
        self.addCleanup(self.rm.clear_readonly)

        p = patch_settings(
            DBRECOVER_ATTEMPTS=5,
            DBRECOVER_INTERVAL=0,  # Recover immediately
            DBRECOVER_MULTIPLIER=2,
        )
        p.start()
        self.addCleanup(p.stop)

    def tearDown(self):
        if self.rm.is_failed(self.rm.current_dbid()):
            self.rm.clear_failed(self.rm.current_dbid())
        super(ReadOnlyRecoveryTestCase, self).tearDown()

    def test_readonly_is_automatic(self):
        self.assertTrue(self.rm.current_readonly_is_automatic())

    def test_readonly_doesnt_override_auto(self):
        self.rm.mark_current_failed(automatic=True)
        self.assertTrue(self.rm.current_readonly_is_automatic())

    def test_recovers(self):
        self.rm.check_readonly()
        self.assertFalse(settings.READ_ONLY_MODE)

    def test_recovery_fail_increments_attempts(self):
        self.rm.mark_current_failed(automatic=True)
        self.assertEqual(2, self.rm.current_readonly_attempts())
        self.rm.ping_current_connection = self.mock_ping_current_connection
        self.rm.check_readonly()
        self.assertTrue(settings.READ_ONLY_MODE)
        self.assertEqual(3, self.rm.current_readonly_attempts())

    def test_recovery_stops_after_attempts(self):
        self.rm.ping_current_connection = self.mock_ping_current_connection
        for i in range(settings.DBRECOVER_ATTEMPTS):
            self.assertTrue(self.rm.next_recovery_due() is not None)
            self.rm.check_readonly()
        self.assertTrue(self.rm.next_recovery_due() is None)

    def test_automatic_failover_with_manual_recovery(self):
        # trigger an automatic failover due to the master db being down
        self.rm.mark_failed(self.rm.master_dbid(), automatic=True)
        self.addCleanup(self.rm.clear_failed, self.rm.master_dbid())
        self.addCleanup(self.rm.clear_readonly)

        mock_clear_readonly = Mock()
        with patch.object(self.rm, 'clear_readonly', mock_clear_readonly):
            with patch.multiple(settings, DBRECOVER_ATTEMPTS=0):
                # make sure next_recovery_due will return None
                self.assertIsNone(self.rm.next_recovery_due())
                # probe connection
                self.rm.check_readonly()
            self.assertFalse(mock_clear_readonly.called)
        self.assertTrue(settings.READ_ONLY_MODE)

    def test_leave_readonly_doesnt_enable_db_connection(self):
        # simulate a normal db failure
        self.rm.mark_current_failed(automatic=True)
        with patch.object(self.rm, 'is_failed') as mock_is_failed:
            mock_is_failed.return_value = True
            self.rm.clear_readonly()
            self.rm.check_readonly()
            # as the db is still failing readonly is enabled automatically
            self.assertTrue(settings.READ_ONLY_MODE)

    def test_readonly_doesnt_break_with_no_json(self):
        f = open(self.rm.readonly_marker_file, 'w')
        f.close()  # Thus leaving the file empty
        rm = ReadOnlyManager()
        rm.check_readonly()
        self.assertFalse(settings.READ_ONLY_MODE)

    def test_readonly_doesnt_break_with_invalid_json(self):
        f = open(self.rm.readonly_marker_file, 'w')
        f.write('}so 0o; invalid"#')
        f.close()
        rm = ReadOnlyManager()
        rm.check_readonly()
        self.assertFalse(settings.READ_ONLY_MODE)

    def mock_ping_current_connection(self):
        return False


class ReadOnlyFlagFilesTestCase(ReadOnlyBaseTestCase):

    def test_flag_files_in_right_directory(self):
        self.rm.set_readonly()
        flags = os.listdir(settings.DBFAILOVER_FLAG_DIR)
        self.assertTrue('db.readonly' in flags)

    def test_readonly_flag_files_have_right_mode(self):
        self.rm.set_readonly()
        mode = os.stat(self.rm.readonly_marker_file)[stat.ST_MODE]
        self.assertTrue(mode & stat.S_IRGRP)
        self.assertTrue(mode & stat.S_IWGRP)

    def test_dbfail_flag_files_have_right_mode(self):
        self.rm.mark_failed('foo')
        flagfile = self.rm.marker_file_pattern % 'foo'
        mode = os.stat(flagfile)[stat.ST_MODE]
        self.assertTrue(mode & stat.S_IRGRP)
        self.assertTrue(mode & stat.S_IWGRP)


class ReadOnlyDataTestCase(ReadOnlyBaseTestCase):

    def test_readonly_returns_404_for_get(self):
        response = self.client.get('/readonlydata')
        self.assertEqual(404, response.status_code)

    def test_readonly_returns_404_without_readonly_secret(self):
        response = self.client.post('/readonlydata')
        self.assertEqual(404, response.status_code)

    def test_readonly_returns_404_with_bad_secret(self):
        data = {'secret': 'something different'}
        response = self.client.post('/readonlydata', data)
        self.assertEqual(404, response.status_code)

    def test_readonly_returns_200_with_right_secret(self):
        data = {'secret': settings.READONLY_SECRET}
        response = self.client.post('/readonlydata', data)
        self.assertEqual(200, response.status_code)

    def test_readonly_data(self):
        post = {'secret': settings.READONLY_SECRET}
        response = self.client.post('/readonlydata', post)
        data = json.loads(response.content)
        self.assertTrue('readonly' in data)
        self.assertTrue('connections' in data)

    def test_readonly_set_readonly(self):
        post = {'secret': settings.READONLY_SECRET, 'action': 'set'}
        response = self.client.post('/readonlydata', post)
        data = json.loads(response.content)
        self.assertTrue(data['readonly'])

    def test_readonly_clear_readonly(self):
        post = {'secret': settings.READONLY_SECRET, 'action': 'clear'}
        response = self.client.post('/readonlydata', post)
        data = json.loads(response.content)
        self.assertFalse(data['readonly'])

    def test_readonly_disable_master(self):
        post = {'secret': settings.READONLY_SECRET,
                'action': 'disable',
                'conn': 'master'}
        response = self.client.post('/readonlydata', post)
        data = json.loads(response.content)
        self.assertTrue(data['connections'][0]['failed'])
        self.assertTrue(data['readonly'])

    def test_readonly_reenable_master(self):
        post = {'secret': settings.READONLY_SECRET,
                'action': 'disable',
                'conn': 'master'}
        response = self.client.post('/readonlydata', post)
        post['action'] = 'enable'
        response = self.client.post('/readonlydata', post)
        data = json.loads(response.content)
        self.assertFalse(data['connections'][0]['failed'])
        self.assertTrue(data['readonly'])


class ReadOnlyViewsTestCase(ReadOnlyBaseTestCase):

    def login_with_staff(self):
        user = User.objects.create(username='admin')
        user.is_staff = True
        user.set_password('password')
        user.save()
        r = self.client.login(username='admin', password='password')
        self.assertTrue(r)

    def patch_urlopen(self, mock_urlopen=None):
        self.reqs = []

        def _mock_urlopen(req, data=None):
            self.reqs.append(req)
            return StringIO(json.dumps({}))

        if mock_urlopen is None:
            mock_urlopen = _mock_urlopen

        old = urllib2.urlopen
        urllib2.urlopen = mock_urlopen
        self.addCleanup(setattr, urllib2, 'urlopen', old)

    def patch_app_servers_setting(self, new_setting):
        old = settings.APP_SERVERS
        settings.APP_SERVERS = new_setting
        self.addCleanup(setattr, settings, 'APP_SERVERS', old)

    def test_readonly_admin(self):
        self.login_with_staff()

        new_setting = [
            {'SERVER_ID': 'localhost', 'SCHEME': 'http',
             'HOST': 'localhost', 'VIRTUAL_HOST': '',
             'PORT': '8000'}
        ]
        self.patch_app_servers_setting(new_setting)

        expected = [{'appservers': [{'name': 'localhost', 'reachable': False}],
                     'admin_media_prefix': settings.ADMIN_MEDIA_PREFIX,
                     'clear_all_readonly': False,
                     'set_all_readonly': False}]
        r = self.client.get('/readonly')
        self.assertTemplateUsed(r, 'admin/readonly.html')
        for item in r.context:
            self.assertEqual(item.dicts, expected)

    def test_get_server_atts_server_unreachable(self):
        servers = [{'SERVER_ID': 'localhost', 'SCHEME': 'http',
                    'HOST': 'localhost', 'VIRTUAL_HOST': '', 'PORT': '8000'}]
        expected = {'appservers': [{'name': 'localhost', 'reachable': False}],
                    'admin_media_prefix': settings.ADMIN_MEDIA_PREFIX,
                    'clear_all_readonly': False,
                    'set_all_readonly': False}
        atts = get_server_atts(servers)
        self.assertEqual(atts, expected)

    def test_get_server_atts_data_error(self):

        def mock_loads(data):
            raise ValueError()

        old_loads = json.loads
        json.loads = mock_loads
        self.addCleanup(setattr, json, 'loads', old_loads)
        self.patch_urlopen()

        servers = [{'SERVER_ID': 'localhost', 'SCHEME': 'http',
                    'HOST': 'localhost', 'VIRTUAL_HOST': '', 'PORT': '8000'}]
        expected = {'appservers': [{'name': 'localhost', 'reachable': False}],
                    'admin_media_prefix': settings.ADMIN_MEDIA_PREFIX,
                    'clear_all_readonly': False,
                    'set_all_readonly': True}
        atts = get_server_atts(servers)
        self.assertEqual(atts, expected)

    def test_get_server_atts_readonly(self):

        def mock_urlopen(req, data=None):
            data = {'readonly': True}
            return StringIO(json.dumps(data))

        self.patch_urlopen(mock_urlopen=mock_urlopen)

        servers = [{'SERVER_ID': 'localhost', 'SCHEME': 'http',
                    'HOST': 'localhost', 'VIRTUAL_HOST': '', 'PORT': '8000'}]
        expected = {'appservers': [{'name': 'localhost', 'reachable': True,
                                    'readonly': True}],
                    'admin_media_prefix': settings.ADMIN_MEDIA_PREFIX,
                    'clear_all_readonly': True,
                    'set_all_readonly': False}
        atts = get_server_atts(servers)
        self.assertEqual(atts, expected)

    def test_readonly_confirm_get(self):
        self.login_with_staff()

        r = self.client.get('/readonly/localhost/set')
        self.assertTemplateUsed(r, 'admin/readonly_confirm.html')
        self.assertEqual(r.context['appserver'], 'localhost')
        self.assertEqual(r.context['action'], 'set')
        self.assertEqual(r.context['conn'], None)

    def test_readonly_confirm_post(self):
        self.patch_urlopen()
        self.disable_csrf()
        self.addCleanup(self.reset_csrf)
        self.login_with_staff()

        r = self.client.post('/readonly/localhost/set')
        data = map(lambda x: x.data, self.reqs)
        self.assertEqual(data, [
            "action=set&conn=None&secret=%s" % settings.READONLY_SECRET
        ])

        self.assertRedirects(r, '/readonly')

    def test_update_server_all_appservers(self):
        self.patch_urlopen()
        new_setting = [
            {'SERVER_ID': 'localhost', 'SCHEME': 'http',
             'HOST': 'localhost', 'VIRTUAL_HOST': '', 'PORT': '8000'},
            {'SERVER_ID': 'otherhost', 'SCHEME': 'http',
             'HOST': 'otherhost', 'VIRTUAL_HOST': '', 'PORT': '8000'},
        ]
        self.patch_app_servers_setting(new_setting)
        update_server('set')
        data = map(lambda x: x.data, self.reqs)
        self.assertEqual(data, [
            "action=set&conn=None&secret=%s" % settings.READONLY_SECRET,
            "action=set&conn=None&secret=%s" % settings.READONLY_SECRET
        ])

    def test_update_server_one_appserver(self):
        self.patch_urlopen()
        new_setting = [
            {'SERVER_ID': 'localhost', 'SCHEME': 'http',
             'HOST': 'localhost', 'VIRTUAL_HOST': '', 'PORT': '8000'},
            {'SERVER_ID': 'otherhost', 'SCHEME': 'http',
             'HOST': 'otherhost', 'VIRTUAL_HOST': '', 'PORT': '8000'},
        ]
        self.patch_app_servers_setting(new_setting)
        update_server('set', 'localhost')
        data = map(lambda x: x.data, self.reqs)
        self.assertEqual(data, [
            "action=set&conn=None&secret=%s" % settings.READONLY_SECRET
        ])

    def test_update_server_one_connection(self):
        self.patch_urlopen()
        new_setting = [
            {'SERVER_ID': 'localhost', 'SCHEME': 'http',
             'HOST': 'localhost', 'VIRTUAL_HOST': '', 'PORT': '8000'},
        ]
        self.patch_app_servers_setting(new_setting)
        update_server('set', 'localhost', 'master')
        data = map(lambda x: x.data, self.reqs)
        self.assertEqual(data, [
            "action=set&conn=master&secret=%s" % settings.READONLY_SECRET,
        ])
