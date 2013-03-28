# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

import psycopg2
from psycopg2 import DatabaseError


class MockCursor(object):
    def __init__(self, data=None, connection=None):
        self.data = data
        self.connection = connection

    def execute(self, query, params):
        return True

    def fetchone(self):
        if self.data:
            return self.data[0]

    def fetchmany(self, size=None):
        if size is not None:
            return self.data[:size]
        else:
            return self.data


class MockConnection(object):
    def __init__(self, connection, psycopg):
        self.connection = connection
        self.psycopg = psycopg

    def cursor(self):
        if self.psycopg.fail_next_N_connections > 0:
            self.psycopg.fail_next_N_connections -= 1
            raise DatabaseError('Mock error.')
        return self.connection.cursor()

    def __getattr__(self, attr):
        if attr in self.__dict__:
            return self.__dict__[attr]
        else:
            return getattr(self.connection, attr)


class MockPsycopg(object):
    def __init__(self):
        self.fail_next_N_connections = 0
        self.dsn = None

    def connect(self, *args, **kwargs):
        if self.fail_next_N_connections > 0:
            self.fail_next_N_connections -= 1
            raise DatabaseError('Mock error.')
        if self.conn_params is not None:
            args = []
            kwargs = self.conn_params
        return MockConnection(psycopg2.connect(*args, **kwargs), self)

    def fixate_connection(self, conn_params):
        """ Fixate the database connection information.

        This function ensures that further connections will be
        attempted always using the same connection info, so that we
        can play around with the DATABASES settings during tests and still keep
        connecting to our only test database. """
        self.conn_params = conn_params

    def release_connection(self):
        """ Release the database connection information.

        Forget about stored connection information, so that next
        call to connect() really connects to the database you ask
        for. """
        self.conn_params = None

mock = MockPsycopg()
connect = mock.connect
fixate_connection = mock.fixate_connection
release_connection = mock.release_connection


def fail_next_N_connections(n):
    mock.fail_next_N_connections = n
