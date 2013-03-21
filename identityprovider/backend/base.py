# Copyright 2010, 2012 Canonical Ltd.  This software is licensed under
# the GNU Affero General Public License version 3 (see the file
# LICENSE).

__all__ = [
    'DatabaseWrapper', 'DatabaseError', 'IntegrityError',
]

import re
from hashlib import sha1

from django.conf import settings
from django.core.cache import cache
from django.db.utils import DatabaseError, IntegrityError
from django.utils.translation import ugettext as _

from .old import base as old_base


class BaseCache(object):
    """This class provides a cached version of a single database table.

    Queries are routed through memcached first, so only cache misses
    really hit the database.  Inserts and deletes are carried out
    in memcached only, so that the database is never written to.

    Subclasses need to implement update if needed.
    """
    table = None
    primary_key = None

    def insert(self, match, params, cursor):
        """Insert the row only into memcached."""
        cols = [x.strip('",') for x in match.group('cols').split()]
        values = dict(zip(cols, params))
        key = self.cache_key(values[self.primary_key])
        cache.add(key, str([params]))

    def select(self, match, params, cursor):
        """Check memcached first, then hit the DB if not found."""
        pkey_cond = '"%s"."%s" = %%s' % (self.table, self.primary_key)
        assert pkey_cond in match.group('cond')
        key = self.cache_key(params[0])
        cached_value = cache.get(key)
        if cached_value is None:
            cursor.execute(match.group(0), params)
            cached_value = cursor.fetchmany()
        else:
            cached_value = eval(cached_value)
        return cached_value

    def delete(self, match, params, cursor):
        """Mark the row as deleted in memcached.

        Note that future queries to this row will produce no results,
        even if there's an entry in the DB for it.
        """
        delete_pattern = r'"%s" IN \(%%s\)' % self.primary_key
        assert re.match(delete_pattern, match.group('cond'))
        for dbkey in params[0]:
            key = self.cache_key(dbkey)
            cache.set(key, '[]')

    def cache_key(self, dbkey):
        """Returns a canonical memcached key for a row in a table."""
        hash = sha1(dbkey).hexdigest()
        return 'db-%s-%s' % (self.table, hash)


class OpenIDAssociationCache(BaseCache):
    table = 'openidassociation'
    primary_key = 'handle'


class DjangoSessionCache(BaseCache):
    table = 'django_session'
    primary_key = 'session_key'

    def update(self, match, params, cursor):
        """django_session is always updated in the same way, so we can map
        that in to a row in the database.
        """
        pkey_cond = '"%s"."%s" = %%s' % (self.table, self.primary_key)
        assert pkey_cond == match.group('cond').strip()
        update_format = '"session_data" = %s, "expire_date" = %s'
        assert update_format == match.group('cols')
        key = self.cache_key(params[2])
        new_value = [params[2], params[0], params[1]]
        cache.set(key, str([new_value]))


class AuthUserCache(BaseCache):
    table = 'auth_user'
    primary_key = 'auth_user_pkey'

    def select(self, match, params, cursor):
        """Skip memcached completely."""
        cursor.execute(match.group(0), params)
        cached_value = cursor.fetchmany()
        return cached_value

    def update(self, match, params, cursor):
        """Does nothing.
        During readonly mode auth_user will only be updated to set
        last_login, so we ignore all updates.
        """
        pass

cached_tables = {
    'django_session': DjangoSessionCache(),
    'openidassociation': OpenIDAssociationCache(),
    'auth_user': AuthUserCache(),
}


class CursorReadOnlyWrapper(object):
    command_patterns = {
        'delete': r'^DELETE FROM "(?P<table>.*)" WHERE (?P<cond>.*)$',
        'insert': (r'^INSERT INTO "(?P<table>.*)" \((?P<cols>.*)\) '
                   r'VALUES \((?P<values>.*)\)$'),
        'select': (r'^SELECT (?P<cols>.*) FROM "(?P<table>.*)" '
                   r'WHERE (?P<cond>.*)$'),
        'update': (r'^UPDATE "(?P<table>.*)" SET (?P<cols>.*) '
                   r'WHERE (?P<cond>.*)$'),
    }

    def __init__(self, cursor):
        self.cursor = cursor
        self.cache = None

    def execute_cached(self, command, sql, params):
        """Attempt to carry out a command against memcache.

        Return True if the command is successfully carried out.
        """
        pattern = self.command_patterns.get(command)
        if pattern is None:
            return False
        match = re.match(pattern, sql)
        if match is not None:
            table = match.group('table')
            if table in cached_tables:
                self.cache = cached_tables[table]
                method = getattr(self.cache, command)
                self._values = method(match, params, self.cursor)
                return True
        return False

    def execute(self, sql, params=()):
        command = sql.split(' ', 1)[0].lower()
        executed = self.execute_cached(command, sql, params)
        if executed:
            return
        if command in ['select', 'savepoint']:
            return self.cursor.execute(sql, params)
        else:
            msg = (_('Attempted to %(command)s while in '
                     'read-only mode: \'%(sql)s\' %% (%(params)s)') %
                   {'command': command, 'sql': sql, 'params': params})
            raise DatabaseError(msg)

    def fetchone(self):
        if self.cache is not None:
            if len(self._values) == 0:
                return None
            value = self._values[0]
            self._values = self._values[1:]
            return value
        else:
            return self.cursor.fetchone()

    def fetchmany(self, chunk):
        if self.cache is not None:
            if len(self._values) == 0:
                raise StopIteration()
            values = self._values[:chunk]
            self._values = self._values[chunk:]
            return values
        else:
            return self.cursor.fetchmany(chunk)

    def __getattr__(self, attr):
        return getattr(self.cursor, attr)


class DatabaseWrapper(old_base.DatabaseWrapper):

    def _cursor(self, *args):
        cursor = super(DatabaseWrapper, self)._cursor(*args)

        if settings.READ_ONLY_MODE:
            cursor = CursorReadOnlyWrapper(cursor)

        return cursor
