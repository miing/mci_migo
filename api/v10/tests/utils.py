# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

import base64
from urlparse import urlparse

from django.conf import settings
from django.core.handlers.wsgi import WSGIHandler
from django.test import TestCase
from lazr.restfulclient.resource import ServiceRoot
from u1testutils.wsgi_intercept import WSGIInterceptedTestCase

from identityprovider.tests.utils import SSOBaseTransactionTestCase
from identityprovider.tests.factory import SSOObjectFactory

from api.v10.handlers import (
    LazrRestfulHandler,
)


def http_authorization_extra(email_address, password):
    email_address = base64.b64encode('%s:%s' % (email_address, password))
    return {'HTTP_AUTHORIZATION': 'basic ' + email_address}


class AnonAPITestCase(SSOBaseTransactionTestCase, WSGIInterceptedTestCase):
    factory = SSOObjectFactory()

    def setUp(self):
        super(AnonAPITestCase, self).setUp()
        parse = urlparse(settings.API_HOST)
        callbacks = {
            'default': WSGIHandler,
            (parse.hostname, parse.port): WSGIHandler,
        }
        self.setup_intercept(callbacks, intercept_api=True)
        self.api = ServiceRoot(
            None, settings.API_HOST.rstrip('/') + '/api/1.0'
        )
        self.addCleanup(self.teardown_intercept)


class TestLazrRestfulHandler(TestCase):
    handler = LazrRestfulHandler()

    def test_named_operation_error_is_plaintext(self):
        script = '<script>alert("boo");</script>'
        response = self.handler.named_operation(None, {'ws.op': script})
        self.assertEqual(response['content-type'], 'text/plain')

    def test_create_error_is_plaintext(self):
        request = MockRequest()
        request.POST = {}
        response = self.handler.create(request)
        self.assertEqual(response['content-type'], 'text/plain')


class MockRequest(object):
    def __init__(self, data=None, user=None):
        self.user = user
        if data is None:
            data = {}
        self.data = data
        self.environ = {'REMOTE_ADDR': '127.0.0.1'}
