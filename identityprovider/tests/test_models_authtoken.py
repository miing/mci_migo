# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

import random

from datetime import datetime
from urlparse import urljoin

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.urlresolvers import reverse
from mock import patch

from identityprovider.models.account import Account
from identityprovider.models import (
    AuthToken,
    EmailAddress,
    authtoken,
)
from identityprovider.models.const import TokenType
from identityprovider.tests.utils import SSOBaseTestCase


class AuthTokenManagerTestCase(SSOBaseTestCase):

    def test_valid_email(self):
        emails = {'valid': ['kiko.async@hotmail.com', 'kiko+async@hotmail.com',
                            'kiko-async@hotmail.com', 'kiko_async@hotmail.com',
                            'kiko@async.com.br', 'kiko@canonical.com',
                            'kiko@UBUNTU.COM', 'kiko@gnu.info',
                            'user@z.de', 'bob=dobbs@example.com',
                            'keith@risby-family.co.uk'],
                  'invalid': ['user@z..de', 'user@.z.de', 'i@tv',
                              'keith@risby-family-.co.uk',
                              'keith@-risby-family.co.uk']}
        for email in emails['valid']:
            t = AuthToken.objects.create(
                email=email, token_type=TokenType.VALIDATEEMAIL)
            self.assertEqual(t.email, email)
        for email in emails['invalid']:
            self.assertRaises(ValidationError, AuthToken.objects.create,
                              email=email, token_type=TokenType.VALIDATEEMAIL)

    def test_token_invalid_type(self):
        good_types = [TokenType.PASSWORDRECOVERY,
                      TokenType.VALIDATEEMAIL,
                      TokenType.INVALIDATEEMAIL,
                      TokenType.NEWPERSONLESSACCOUNT]
        for token_type in good_types:
            token = AuthToken.objects.create(email='mark@example.com',
                                             token_type=token_type)
            self.assertEqual(token.token_type, token_type)

        bad_types = [t[0] for t in TokenType._get_choices()
                     if t[0] not in good_types]
        for token_type in bad_types:
            self.assertRaises(ValueError, AuthToken.objects.create,
                              email='mark@example.com', token_type=token_type)

    def test_token_is_set(self):
        token = AuthToken.objects.create(
            email='mark@example.com', token_type=TokenType.VALIDATEEMAIL)
        self.assertIsNotNone(token.token)
        self.assertEqual(len(token.token), 6)

    def test_token_is_not_overwritten(self):
        token_string = '123LMN456ZKW'
        token = AuthToken.objects.create(
            email='mark@example.com', token=token_string,
            token_type=TokenType.VALIDATEEMAIL)
        self.assertEqual(token.token, token_string)


class AuthTokenTestCase(SSOBaseTestCase):

    fixtures = ["test"]
    email = 'test@canonical.com'
    new_email = 'email@domain.com'

    def setUp(self):
        super(AuthTokenTestCase, self).setUp()
        self.account = Account.objects.get_by_email(self.email)

        assert EmailAddress.objects.filter(email=self.new_email).count() == 0

    def test_absolute_url(self):
        for t, name in TokenType._get_choices():
            token_string = str(t).ljust(6, 'x')
            token = AuthToken(
                token_type=t, email=self.new_email, token=token_string,
            )
            token.save()  # do not use the manager since types are restricted
            name = 'claim_token'
            kwargs = dict(authtoken=token_string)
            if t in authtoken.urls_mapping:
                name = authtoken.urls_mapping[t]
                kwargs['email_address'] = self.new_email

            url = reverse(name, kwargs=kwargs)
            self.assertEqual(token.absolute_url,
                             urljoin(settings.SSO_ROOT_URL, url))

    def test_consume(self):
        email = 'mark@example.com'
        token_type = TokenType.NEWPERSONLESSACCOUNT
        # need more than one token to fully test the method
        token = AuthToken.objects.create(
            email=email, token_type=token_type, token='a')
        token2 = AuthToken.objects.create(
            email=email, token_type=token_type, token='b')
        self.assertIsNone(token.date_consumed)
        self.assertIsNone(token2.date_consumed)

        token.consume()

        tokens = AuthToken.objects.filter(
            email=token.email, token_type=token.token_type,
            requester=token.requester)
        self.assertEqual(tokens.count(), 2)
        self.assertIsNotNone(tokens[0].date_consumed)
        self.assertIsNotNone(tokens[1].date_consumed)

    @patch('identityprovider.models.authtoken.datetime')
    def test_consume_use_utc(self, mock_datetime):
        now = datetime.utcnow()
        mock_datetime.datetime.utcnow.return_value = now

        email = 'mark@example.com'
        token_type = TokenType.NEWPERSONLESSACCOUNT
        # need more than one token to fully test the method
        token = AuthToken.objects.create(
            email=email, token_type=token_type, token='a')
        token2 = AuthToken.objects.create(
            email=email, token_type=token_type, token='b')
        self.assertIsNone(token.date_consumed)
        self.assertIsNone(token2.date_consumed)

        token.consume()

        tokens = AuthToken.objects.filter(
            email=token.email, token_type=token.token_type,
            requester=token.requester)
        self.assertEqual(tokens.count(), 2)
        self.assertEqual(tokens[0].date_consumed, now)
        self.assertEqual(tokens[1].date_consumed, now)
        self.assertEqual(mock_datetime.datetime.utcnow.called, True)

    def test_create_unique_token_for_table(self):
        # initialize randomizer
        random.seed(42)

        # create a token
        token1 = authtoken.create_unique_token_for_table(1, AuthToken, 'token')
        # use that token within an AuthToken
        AuthToken.objects.create(
            email='mark@example.com',
            token_type=TokenType.NEWPERSONLESSACCOUNT, token=token1)

        # reinitialize randomizer to force same token
        random.seed(42)
        token2 = authtoken.create_unique_token_for_table(1, AuthToken, 'token')
        self.assertNotEqual(token1, token2)

    def test_active(self):
        t = AuthToken.objects.create(
            token_type=TokenType.NEWPERSONLESSACCOUNT, email=self.new_email)
        self.assertTrue(t.active)

        t.consume()
        self.assertFalse(t.active)
