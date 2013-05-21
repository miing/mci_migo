# encoding: utf-8

from django.utils import simplejson as json
from datetime import datetime

from django.conf import settings
from mock import patch

from identityprovider.tests import DEFAULT_USER_PASSWORD
from identityprovider.tests.utils import (
    SSOBaseTestCase,
    authorization_header_from_token,
)

from api.v10.tests.utils import http_authorization_extra
from api.v10.tests.test_handlers import AuthenticationTestCase


class Authentication11TestCase(AuthenticationTestCase):

    def test_authenticate_create_token(self):
        expected_keys = ['consumer_key', 'consumer_secret', 'name', 'token',
                         'token_secret', 'created', 'updated']

        for token_name in ('some-token', '"some-token"'):
            content = self.authenticate(token_name=token_name, method='POST',
                                        api_version='1.1')
            self.assertEqual(set(content.keys()), set(expected_keys))
            self.assertEqual(content['name'], 'some-token')

    def test_authenticate_refresh_existing_token(self):
        expected_keys = ['consumer_key', 'consumer_secret', 'name', 'token',
                         'token_secret', 'created', 'updated']

        class MockDateTime(datetime):

            @classmethod
            def utcnow(cls):
                return datetime(2222, 2, 22, 22, 22, 22)

        token1 = self.authenticate(token_name='some-token')
        # patch the datetime so we can assert a new value was set for token2
        with patch('api.v11.handlers.datetime', MockDateTime):
            token2 = self.authenticate(token_name='some-token',
                                       token=token1['token'],
                                       api_version='1.1',
                                       method='PUT')

        self.assertEqual(set(token1.keys()), set(expected_keys))
        self.assertEqual(set(token2.keys()), set(expected_keys))

        for key in expected_keys:
            if key == 'updated':
                self.assertNotEqual(token1[key], token2[key])
                self.assertEqual(token2[key], '2222-02-22 22:22:22')
            else:
                self.assertEqual(token1[key], token2[key])

    def test_authenticate_refresh_account_has_no_tokens(self):
        extra = http_authorization_extra(self.email_address,
                                         password=DEFAULT_USER_PASSWORD)
        data = {
            'ws.op': 'authenticate',
            'token_name': 'some-token',
            'token': 'some-data'
        }

        # the account has no tokens at all
        assert len(self.account.oauth_tokens()) == 0

        response = self.put('/api/1.1/authentications', data, **extra)
        self.assertEqual(response.status_code, 404)

    def test_authenticate_refresh_token_is_not_owned(self):
        extra = http_authorization_extra(self.email_address,
                                         password=DEFAULT_USER_PASSWORD)
        data = {
            'ws.op': 'authenticate',
            'token_name': 'some-token',
            'token': 'some-data'
        }

        # the account has at least a token, but it's not the one
        # we're refreshing
        self.account.create_oauth_token('foobar')
        assert len(self.account.oauth_tokens()) == 1

        response = self.put('/api/1.1/authentications', data, **extra)
        self.assertEqual(response.status_code, 404)

    def test_authenticate_get_has_no_side_effects(self):
        # create a token
        token1 = self.authenticate(token_name='some-token', api_version='1.1',
                                   method='POST')
        with patch('oauth_backend.models.Token.save') as mock_save:
            # get it again
            token2 = self.authenticate(token_name='some-token',
                                       api_version='1.1')
        # nothing has changed
        self.assertEqual(token1, token2)
        # and no side effects
        self.assertFalse(mock_save.called)


class BackwardsCompatibleApi11TestCase(SSOBaseTestCase):
    def test_root_handler(self):
        api_base_url = "%sapi/1.1" % settings.SSO_ROOT_URL
        expected = {
            "registrations_collection_link": "%s/registration" % api_base_url,
            "captchas_collection_link": "%s/captchas" % api_base_url,
            "authentications_collection_link": (
                "%s/authentications" % api_base_url),
            "resource_type_link": "%s/#service-root" % api_base_url,
            "accounts_collection_link": "%s/accounts" % api_base_url,
        }
        response = self.client.get('/api/1.1/', HTTP_ACCEPT='text/html')
        content = json.loads(response.content)
        self.assertEqual(content, expected)

    def test_captchas_fallback(self):
        with patch('api.v10.handlers.CaptchaHandler.read') as mock_captchas:
            self.client.get('/api/1.1/captchas', HTTP_ACCEPT='text/html')
        self.assertTrue(mock_captchas.called)

    def test_registration_fallback(self):
        handler = 'api.v10.handlers.RegistrationHandler.read'
        with patch(handler) as mock_registration:
            self.client.get('/api/1.1/registration', HTTP_ACCEPT='text/html')
        self.assertTrue(mock_registration.called)

    def test_accounts_fallback(self):
        with patch('api.v10.handlers.AccountsHandler.read') as mock_accounts:
            account = self.factory.make_account()
            token = account.create_oauth_token('token-name')
            url = '/api/1.1/accounts'
            self.client.get('/api/1.1/accounts', HTTP_ACCEPT='text/html',
                            **authorization_header_from_token(url, token))
        self.assertTrue(mock_accounts.called)
