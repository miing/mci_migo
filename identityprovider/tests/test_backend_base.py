# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

import re
import random

from django.conf import settings
from django.core.cache import cache
from django.db import DEFAULT_DB_ALIAS
from django.db.backends.postgresql_psycopg2.base import (
    DatabaseWrapper as PostgresDatabaseWrapper)
from django.test import TestCase

from identityprovider.backend.base import (
    AuthUserCache, CursorReadOnlyWrapper, DatabaseError, DatabaseWrapper,
    BaseCache, DjangoSessionCache)
from identityprovider.readonly import ReadOnlyManager
from identityprovider.tests.mockdb import MockCursor
from identityprovider.tests.utils import skipOnSqlite

from identityprovider.tests.test_backend_old_base import (
    DatabaseWrapperTestCase as OldDatabaseWrapperTestCase)


class BaseCacheTestCase(TestCase):

    def setUp(self):
        super(BaseCacheTestCase, self).setUp()
        # initialize random number generator
        random.seed(42)
        # start with empty cache
        cache.clear()

        self.cursor = MockCursor("'value'")

        self.base_cache = BaseCache()
        self.base_cache.table = "t"
        self.base_cache.primary_key = "w"
        self.match = re.match(CursorReadOnlyWrapper.command_patterns['select'],
                              'SELECT "a", "b" FROM "t" WHERE "t"."w" = %s')

    def test_select_when_no_cached_value(self):
        value = self.base_cache.select(self.match, ["1"], self.cursor)

        self.assertEqual(value, "'value'")

    def test_select_when_there_is_cached_value(self):
        cache.add(self.base_cache.cache_key("1"), "'VALUE'")
        value = self.base_cache.select(self.match, ["1"], self.cursor)

        self.assertEqual(value, "VALUE")


class DjangoSessionCacheTestCase(TestCase):

    def test_update(self):
        mock = MockCursor("value")
        match = re.match(
            CursorReadOnlyWrapper.command_patterns['update'],
            'UPDATE "t" SET "session_data" = %s, "expire_date" = %s '
            'WHERE "django_session"."session_key" = %s')
        django_session_cache = DjangoSessionCache()
        django_session_cache.update(match, ["a", "b", "c"], mock)

        value = cache.get(django_session_cache.cache_key("c"))
        self.assertEqual(value, "[['c', 'a', 'b']]")


class CursorReadOnlyWrapperTestCase(TestCase):

    def setUp(self):
        super(CursorReadOnlyWrapperTestCase, self).setUp()
        # initialize random number generator
        random.seed(42)
        # start with empty cache
        cache.clear()
        self.cursor = MockCursor()
        self.wrapper = CursorReadOnlyWrapper(self.cursor)

    def test_init(self):
        self.assertEqual(self.wrapper.cursor, self.cursor)
        self.assertEqual(self.wrapper.cache, None)

    def test_execute_cached_bad_command(self):
        sql = ''
        params = []
        cached = self.wrapper.execute_cached('', sql, params)
        self.assertFalse(cached)

    def test_execute_cached_bad_sql(self):
        sql = ''
        params = []
        cached = self.wrapper.execute_cached('select', sql, params)
        self.assertFalse(cached)

    def test_execute_cached_non_cached_table(self):
        sql = 'SELECT * FROM "account" WHERE account_pkey = %s'
        params = ['1']
        cached = self.wrapper.execute_cached('select', sql, params)
        self.assertFalse(cached)

    def test_execute_cached_select(self):
        sql = 'SELECT * FROM "auth_user" WHERE auth_user_pkey = %s'
        params = ['1']
        self.cursor.data = expected_values = [('auth_user_pkey', '1'),
                                              ('username', 'user')]
        cached = self.wrapper.execute_cached('select', sql, params)
        self.assertTrue(cached)
        self.assertEqual(self.wrapper._values, expected_values)

    def test_execute_cached_insert(self):
        sql = ('INSERT INTO "auth_user" (auth_user_pkey, username) '
               'VALUES (%s, %s)')
        params = ['1', 'user']
        cached = self.wrapper.execute_cached('insert', sql, params)
        self.assertTrue(cached)
        key = self.wrapper.cache.cache_key('1')
        self.assertEqual(cache.get(key), str([params]))

    def test_execute_cached_delete(self):
        sql = 'DELETE FROM "auth_user" WHERE "auth_user_pkey" IN (%s)'
        params = ['1']
        cached = self.wrapper.execute_cached('delete', sql, params)
        self.assertTrue(cached)
        key = self.wrapper.cache.cache_key('1')
        self.assertEqual(cache.get(key), '[]')

    def test_execute_cached_update(self):
        sql = 'UPDATE "auth_user" SET username=%s WHERE auth_user_pkey=%s'
        params = ['user', '1']
        cached = self.wrapper.execute_cached('update', sql, params)
        self.assertTrue(cached)
        key = self.wrapper.cache.cache_key('1')
        self.assertEqual(cache.get(key), None)

    def test_execute_when_cached(self):
        sql = 'SELECT * FROM "auth_user" WHERE auth_user_pkey=%s'
        params = ['1']
        self.cursor.data = [('auth_user_pkey', '1'),
                            ('username', 'user')]
        result = self.wrapper.execute(sql, params)
        # query was cached
        self.assertEqual(result, None)

    def test_execute_select(self):
        sql = 'SELECT * FROM "account"'
        self.cursor.data = [('account_pkey', '1'),
                            ('displayname', 'Sample Person')]
        result = self.wrapper.execute(sql)
        # query was not cached
        self.assertTrue(result)

    def test_execute_modify(self):
        sql = ('INSERT INTO "account" (account_pkey, displayname) '
               'VALUES (%s, %s)')
        params = ['1', 'Sample Person']
        self.assertRaises(DatabaseError, self.wrapper.execute, sql, params)

    def test_fetchone_not_cached(self):
        self.cursor.data = expected_values = [('auth_user_pkey', '1')]
        result = self.wrapper.fetchone()
        self.assertEqual(self.wrapper.cache, None)
        self.assertEqual(result, expected_values[0])

    def test_fetchone_cached(self):
        self.cursor.data = expected_values = [('auth_user_pkey', '1')]
        sql = 'SELECT * FROM "auth_user" WHERE auth_user_pkey=%s'
        params = ['1']
        self.wrapper.execute_cached('select', sql, params)
        result = self.wrapper.fetchone()
        self.assertTrue(isinstance(self.wrapper.cache, AuthUserCache))
        self.assertEqual(result, expected_values[0])

    def test_fetchone_cache_empty(self):
        self.cursor.data = []
        sql = 'SELECT * FROM "auth_user" WHERE auth_user_pkey=%s'
        params = ['1']
        self.wrapper.execute_cached('select', sql, params)
        self.assertEqual(self.wrapper.fetchone(), None)

    def test_fetchmany_not_cached(self):
        self.cursor.data = expected_values = [('auth_user_pkey', '1'),
                                              ('username', 'user')]
        result = self.wrapper.fetchmany(100)
        self.assertEqual(self.wrapper.cache, None)
        self.assertEqual(result, expected_values)

    def test_fetchmany_cached(self):
        self.cursor.data = expected_values = [('auth_user_pkey', '1'),
                                              ('username', 'user')]
        sql = 'SELECT * FROM "auth_user" WHERE auth_user_pkey=%s'
        params = ['1']
        self.wrapper.execute_cached('select', sql, params)
        result = self.wrapper.fetchmany(100)
        self.assertTrue(isinstance(self.wrapper.cache, AuthUserCache))
        self.assertEqual(result, expected_values)

    def test_fetchmany_cache_empty(self):
        self.cursor.data = []
        sql = 'SELECT * FROM "auth_user" WHERE auth_user_pkey=%s'
        params = ['1']
        self.wrapper.execute_cached('select', sql, params)
        self.assertRaises(StopIteration, self.wrapper.fetchmany, 100)

    def test_getattr(self):
        # test wrapper attribute
        self.assertEqual(self.wrapper.cache, None)
        # test cursor attribute
        self.assertEqual(self.wrapper.connection, None)


@skipOnSqlite
class DatabaseWrapperTestCase(OldDatabaseWrapperTestCase):

    def setUp(self):
        super(DatabaseWrapperTestCase, self).setUp()
        db = settings.DATABASES[DEFAULT_DB_ALIAS]
        db['ENGINE'] = 'identityprovider.backend'
        self.rm = ReadOnlyManager()

        self.settings_dict = {
            'TIME_ZONE': settings.TIME_ZONE,
        }

        db_settings = {}
        for attr in ('HOST', 'NAME', 'OPTIONS', 'PASSWORD', 'PORT', 'USER'):
            db = settings.DATABASES[DEFAULT_DB_ALIAS]
            db_settings[attr] = db.get(attr)

        self.settings_dict.update(db_settings)

    def test_timeout(self):
        old = settings.DB_STATEMENT_TIMEOUT_MILLIS
        try:
            settings.DB_STATEMENT_TIMEOUT_MILLIS = 1
            wrapper = DatabaseWrapper(self.settings_dict)
            cursor = wrapper.cursor()
            try:
                # pg_sleep's argument is seconds
                self.assertRaises(DatabaseError,
                                  cursor.execute, 'SELECT pg_sleep(1)')
            except Exception:
                pass
            finally:
                cursor.connection.close()

        finally:
            settings.DB_STATEMENT_TIMEOUT_MILLIS = old

    def test__cursor_readonly(self):
        self.rm.set_readonly()

        expected_cursor = PostgresDatabaseWrapper(self.settings_dict)._cursor()
        wrapper = DatabaseWrapper(self.settings_dict)
        cursor = wrapper._cursor()
        self.assertTrue(isinstance(cursor, CursorReadOnlyWrapper))
        self.assertEqual(type(cursor.cursor), type(expected_cursor))
        self.assertEqual(cursor.cache, None)

        expected_cursor.connection.close()
        cursor.connection.close()

        self.rm.clear_readonly()

    def test__cursor_not_readonly(self):
        self.rm.clear_readonly()

        expected_cursor = PostgresDatabaseWrapper(self.settings_dict)._cursor()
        wrapper = DatabaseWrapper(self.settings_dict)
        cursor = wrapper._cursor()
        self.assertEqual(type(cursor), type(expected_cursor))

        expected_cursor.connection.close()
        cursor.connection.close()
