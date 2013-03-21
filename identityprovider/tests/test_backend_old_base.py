# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from django.conf import settings
from django.db import DEFAULT_DB_ALIAS
from django.db.backends.postgresql_psycopg2 import base as base_pg
from django.db.backends.util import CursorDebugWrapper, CursorWrapper

from identityprovider.backend.old import base
from identityprovider.tests.utils import SSOBaseTestCase


from identityprovider.tests.utils import skipOnSqlite


@skipOnSqlite
class DatabaseWrapperTestCase(SSOBaseTestCase):

    def setUp(self):
        super(DatabaseWrapperTestCase, self).setUp()
        old_backend = 'identityprovider.backend.old'
        db = settings.DATABASES[DEFAULT_DB_ALIAS]
        db['ENGINE'] = old_backend

        _DEBUG = settings.DEBUG
        self.addCleanup(setattr, settings, 'DEBUG', _DEBUG)

        self.settings_dict = {
            'TIME_ZONE': settings.TIME_ZONE,
        }

        db_settings = {}
        for attr in ('HOST', 'NAME', 'OPTIONS', 'PASSWORD', 'PORT', 'USER'):
            db_settings[attr] = db.get(attr)

        self.settings_dict.update(db_settings)

    def test_cursor_when_debug(self):
        settings.DEBUG = True

        expected_cursor = base_pg.DatabaseWrapper(self.settings_dict).cursor()
        wrapper = base.DatabaseWrapper(self.settings_dict)
        cursor = wrapper.cursor()
        self.assertTrue(isinstance(cursor, CursorDebugWrapper))
        self.assertTrue(isinstance(expected_cursor, CursorDebugWrapper))
        self.assertEqual(cursor.cursor.connection.dsn,
                         expected_cursor.connection.dsn)
        self.assertEqual(cursor.db, wrapper)

        expected_cursor.connection.close()
        cursor.connection.close()

    def test_cursor_when_not_debug(self):
        settings.DEBUG = False

        expected_cursor = base_pg.DatabaseWrapper(self.settings_dict).cursor()
        wrapper = base.DatabaseWrapper(self.settings_dict)
        cursor = wrapper.cursor()
        self.assertTrue(isinstance(cursor, CursorDebugWrapper))
        self.assertTrue(isinstance(expected_cursor, CursorWrapper))
        self.assertEqual(cursor.cursor.connection.dsn,
                         expected_cursor.connection.dsn)
        self.assertEqual(cursor.db, wrapper)

        expected_cursor.connection.close()
        cursor.connection.close()
