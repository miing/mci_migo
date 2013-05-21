# -*- coding: utf-8 -*-

# Copyright 2013 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from django.contrib.auth.signals import user_logged_in
from django.core.urlresolvers import reverse
from django.db.models.signals import post_save

from oauth_backend.models import Token

from identityprovider.const import SESSION_TOKEN_KEY, SESSION_TOKEN_NAME
from identityprovider.signals import (
    invalidate_account_oauth_tokens,
    set_session_oauth_token,
)
from identityprovider.readonly import ReadOnlyManager
from identityprovider.tests import DEFAULT_USER_PASSWORD
from identityprovider.tests.utils import (
    SSOBaseTestCase,
    SSORequestFactory,
    authorization_header_from_token,
)


class SessionTokenOnLoginTestCase(SSOBaseTestCase):

    def setUp(self):
        super(SessionTokenOnLoginTestCase, self).setUp()
        self.email = 'test@canonical.com'
        self.account = self.factory.make_account(email=self.email)
        self.request_factory = SSORequestFactory()

    def test_signal_connected(self):
        # r[1] is a weak ref
        registered_functions = [r[1]() for r in user_logged_in.receivers]
        self.assertIn(set_session_oauth_token, registered_functions)

    def test_listener_default(self):
        assert self.account.oauth_tokens().count() == 0

        self.client.login(username=self.email, password=DEFAULT_USER_PASSWORD)
        oauth_tokens = self.account.oauth_tokens()
        self.assertEqual(oauth_tokens.count(), 1)
        self.assertEqual(
            self.client.session.get(SESSION_TOKEN_KEY), oauth_tokens[0].token)

    def test_listener_checks_for_token_in_header(self):
        token = self.factory.make_oauth_token(account=self.account)
        oauth_header = authorization_header_from_token('/', token)

        url = reverse('login_by_token')
        self.client.get(url, **oauth_header)

        oauth_tokens = self.account.oauth_tokens()
        self.assertIn(token, oauth_tokens)
        self.assertEqual(
            self.client.session.get(SESSION_TOKEN_KEY), token.token)

    def test_listener_read_only_mode_no_token(self):
        rm = ReadOnlyManager()
        rm.set_readonly()
        self.addCleanup(rm.clear_readonly)

        self.client.login(username=self.email, password=DEFAULT_USER_PASSWORD)
        self.assertEqual(Token.objects.count(), 0)
        self.assertEqual(self.client.session.get(SESSION_TOKEN_KEY), '')

    def test_listener_read_only_mode_previous_token(self):
        token = self.factory.make_oauth_token(
            account=self.account, token_name=SESSION_TOKEN_NAME)

        rm = ReadOnlyManager()
        rm.set_readonly()
        self.addCleanup(rm.clear_readonly)

        self.client.login(username=self.email, password=DEFAULT_USER_PASSWORD)
        self.assertEqual(
            self.client.session.get(SESSION_TOKEN_KEY), token.token)


class InvalidateOauthTokenOnPasswordChangeTestCase(SSOBaseTestCase):

    def test_signal_connected(self):
        # r[1] is a weak ref
        registered_functions = [r[1]() for r in post_save.receivers]
        self.assertIn(invalidate_account_oauth_tokens, registered_functions)

    def test_listener_on_password_change(self):
        account = self.factory.make_account()
        self.factory.make_oauth_token(account=account)

        account.set_password('foo')
        self.assertEqual(account.oauth_tokens().count(), 0)
