# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

# Run the app using this WSGI server to run the doctests.
# You'll need to make this accessible on port 80 for the tests to work.

import logging
import os
import signal
import sys
sys.path.append('..')
if 'DJANGO_SETTINGS_MODULE' not in os.environ:
    os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'
import time
from cStringIO import StringIO

from django.conf import settings
from django.core import mail
from django.db import connection
from django.core.handlers.wsgi import WSGIHandler
from django.core.mail.backends import locmem

from wsgiref.simple_server import (
    make_server,
    WSGIRequestHandler,
    ServerHandler,
)
from wsgiref.handlers import format_date_time
from wsgiref.headers import Headers


# Overriding some default settings
settings.SSO_ROOT_URL = 'http://openid.launchpad.dev/'
settings.SSO_PROVIDER_URL = 'http://openid.launchpad.dev/+openid'
settings.OPENID_PREAUTHORIZATION_ACL = (
    ('http://launchpad.dev/', 'http://launchpad.dev/'),
)
settings.SSO_RESTRICT_RP = False
# Set up email sending into a sandbox
mail.SMTPConnection = locmem.EmailBackend
mail.outbox = []

server_port = 80  # We need to be run here for the LP tests to find us

app = WSGIHandler()


class TestingHeaders(Headers):
    """ Same as regular Headers, but join with \n instead of \r\n """
    def __str__(self):
        return '\n'.join(["%s: %s" % kv for kv in self._headers] + ['', ''])


class StatusServerHandler(ServerHandler):
    """ Same as regular ServerHandler, but send a duplicate Status header
        to compensate for zope.testbrowser's behaviour.
        Also, join with \n instead of \r\n.
    """
    headers_class = TestingHeaders

    def send_preamble(self):
        if self.client_is_modern():
            self._write('HTTP/%s %s\n' % (self.http_version, self.status))
            self._write('Status: %s\n' % (self.status.title(),))
            if not self.headers.has_key('Date'):
                self._write(
                    'Date: %s\n' % format_date_time(time.time())
                )
            if self.server_software and not self.headers.has_key('Server'):
                self._write('Server: %s\n' % self.server_software)


class StatusWSGIRequestHandler(WSGIRequestHandler):
    """
    Just like regular WSGIRequestHandlers, but uses
    StatusServerHandler instead of ServerHandler
    """

    verbose = False

    def handle(self):
        self.raw_requestline = self.rfile.readline()
        if not self.parse_request():  # An error code has been sent, just exit
            return

        handler = StatusServerHandler(
            self.rfile, self.wfile, self.get_stderr(), self.get_environ()
        )
        handler.request_handler = self      # backpointer for logging
        handler.run(self.server.get_app())
        if connection.connection is not None:
            connection.connection.close()
        connection.connection = None

    def log_request(self, format, *args):
        if self.verbose:
            WSGIRequestHandler.log_request(self, format, *args)


httpd = make_server('', server_port, app,
                    handler_class=StatusWSGIRequestHandler)

# Setup code coverage tracking
import coverage

if coverage.__version__ >= '3.0':
    cov = coverage.coverage(auto_data=True, data_suffix=True)
else:
    cov = coverage.the_coverage
cov.start()

if '-v' in sys.argv:
    StatusWSGIRequestHandler.verbose = True


# This snippet is required to make the coverage report complete
def signal_handler(signum, frame):
    sys.exit(0)
signal.signal(signal.SIGTERM, signal_handler)

# disable logging
#logging.disable(logging.CRITICAL)
# fake stderr to capture HTTPServer output
# as .serve_forever() will never return until the process is killed, there
# is no need nor reason for restoring stderr afterwards
sys.stderr = StringIO()

print "Serving HTTP on port %s..." % server_port

# Respond to requests until process is killed
httpd.serve_forever()
