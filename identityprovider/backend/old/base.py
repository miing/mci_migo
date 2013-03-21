# Copyright 2010, 2012 Canonical Ltd.  This software is licensed under
# the GNU Affero General Public License version 3 (see the file
# LICENSE).

from django.db.backends.postgresql_psycopg2 import base
from django.conf import settings

DatabaseError = base.DatabaseError
IntegrityError = base.IntegrityError


class DatabaseWrapper(base.DatabaseWrapper):

    def _cursor(self, *args):
        cursor = super(DatabaseWrapper, self)._cursor(*args)

        # This is essentially a no-op if the timeout is 0 (0 means no
        # timeout, and that's the default).
        cursor.execute('SET statement_timeout TO %d' %
                       settings.DB_STATEMENT_TIMEOUT_MILLIS)

        return cursor

    def cursor(self):
        cursor = super(DatabaseWrapper, self).cursor()

        # A "debug cursor" adds statement execution times to the
        # logging stream.  If the app OOPSes, the info can then be
        # included in the report.
        return self.make_debug_cursor(cursor)
