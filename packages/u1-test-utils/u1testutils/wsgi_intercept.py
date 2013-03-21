from __future__ import absolute_import

import sys
import traceback
from httplib import HTTPSConnection
from unittest import TestCase

from wsgi_intercept import (
    add_wsgi_intercept,
    debuglevel,
    remove_wsgi_intercept,
    wsgi_fake_socket,
    WSGI_HTTPConnection,
)
from wsgi_intercept.httplib2_intercept import (
    install,
    uninstall,
)
from wsgi_intercept.urllib2_intercept import (
    install_opener,
    uninstall_opener,
    WSGI_HTTPHandler,
    WSGI_HTTPSHandler,
)


class WSGIInterceptedTestCase(TestCase):
    def setup_intercept(self, callbacks, intercept_api=False):
        """Setup the WSGI intercepts.

        `callbacks` have to be provided to call upon request of the
        intercepted urls. They should be supplied as a dictionary of
        ((hostname, port), callback).

        Additionally one extra `default` callback has to be passed in,
        in the form ('default', callback).

        The `intercept_api` parameter is used to install the `httplib2`
        intercepts, used to intercept the lazr.restful api calls.
        """
        self.patch_wsgi_intercept()

        self.intercepted = []
        install_opener()

        self.intercept_api = intercept_api
        if intercept_api:
            install()

        for key, callback in callbacks.items():
            if key == 'default':
                continue
            host, port = key
            add_wsgi_intercept(host, port, callback)
            self.intercepted.append((host, port))

    def teardown_intercept(self):
        """Remove the installed WSGI intercepts."""
        for host, port in self.intercepted:
            remove_wsgi_intercept(host, port)

        if self.intercept_api:
            uninstall()

        uninstall_opener()

        self.unpatch_wsgi_intercept()

    def patch_wsgi_intercept(self):
        # fix handler order to have highest priority
        self.old_WSGI_HTTPHandler_handler_order = \
            WSGI_HTTPHandler.handler_order
        WSGI_HTTPHandler.handler_order = 1

        if WSGI_HTTPSHandler is not None:
            def https_open(self, req):
                return self.do_open(WSGI_HTTPSConnection, req)

            # use HTTPSHandler for https connections
            self.old_WSGI_HTTPSHandler_https_open = \
                WSGI_HTTPSHandler.https_open
            WSGI_HTTPSHandler.https_open = https_open

            # fix handler order to have highest priority
            self.old_WSGI_HTTPSHandler_handler_order = \
                WSGI_HTTPSHandler.handler_order
            WSGI_HTTPSHandler.handler_order = 1

    def unpatch_wsgi_intercept(self):
        WSGI_HTTPHandler.handler_order = \
            self.old_WSGI_HTTPHandler_handler_order

        if WSGI_HTTPSHandler is not None:
            WSGI_HTTPSHandler.https_open = \
                self.old_WSGI_HTTPSHandler_https_open

            WSGI_HTTPSHandler.handler_order = \
                self.old_WSGI_HTTPSHandler_handler_order

    def parse_urls(self, urls):
        parsed = []
        for url in urls:
            scheme = url.find('://')
            hostport = url[scheme + 3:]
            parts = hostport.split(':')
            host = parts[0]
            if len(parts) == 1:
                if scheme.lower() == 'http':
                    port = 80
                elif scheme.lower() == 'https':
                    port = 443
            else:
                path = parts[1].find('/')
                port = int(parts[1][:path])
            parsed.append((host, port))
        return parsed


#
# WSGI_HTTPConnection
#


class WSGI_HTTPSConnection(HTTPSConnection, WSGI_HTTPConnection):
    def connect(self):
        """
        Override the connect() function to intercept calls to certain
        host/ports.

        If no app at host/port has been registered for interception then
        a normal HTTPConnection is made.
        """
        if debuglevel:
            sys.stderr.write('connect: %s, %s\n' % (self.host, self.port,))

        try:
            (app, script_name) = self.get_app(self.host, self.port)
            if app:
                if debuglevel:
                    sys.stderr.write('INTERCEPTING call to %s:%s\n' %
                                     (self.host, self.port,))
                self.sock = wsgi_fake_socket(app, self.host, self.port,
                                             script_name)
            else:
                HTTPSConnection.connect(self)

        except Exception:
            if debuglevel:              # intercept & print out tracebacks
                traceback.print_exc()
            raise
