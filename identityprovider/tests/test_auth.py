# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).
from django.contrib.auth.models import User

from mock import (
    Mock,
    patch,
)
from oauth_backend.models import (
    Consumer,
    Token,
)
from piston.oauth import OAuthError as PistonOAuthError

from identityprovider.models.account import Account
from identityprovider.models.const import AccountStatus
from identityprovider.models.emailaddress import EmailAddress
from identityprovider.auth import (
    LaunchpadBackend,
    SSOOAuthAuthentication,
    oauth_authenticate,
)
from identityprovider.tests import DEFAULT_USER_PASSWORD
from identityprovider.tests.utils import SSOBaseTestCase


class LaunchpadBackendTestCase(SSOBaseTestCase):

    fixtures = ["test"]

    def setUp(self):
        super(LaunchpadBackendTestCase, self).setUp()
        self.backend = LaunchpadBackend()

    def test_authenticate_with_email_status_not_in_expected_one(self):
        email_address = EmailAddress.objects.get(
            email__iexact="mark@example.com")
        email_address.status = 9999
        email_address.save()

        result = self.backend.authenticate('mark@example.com',
                                           DEFAULT_USER_PASSWORD)

        self.assertTrue(result is None)

    def test_get_user_does_not_exist(self):
        user = self.backend.get_user(9999)
        self.assertTrue(user is None)

    def test_authenticate_with_email_case_insensitive(self):
        # Make sure authentication works as expected
        account1 = self.backend.authenticate('mark@example.com',
                                             DEFAULT_USER_PASSWORD)
        self.assertTrue(account1 is not None)

        # Try using different case for email
        account2 = self.backend.authenticate('Mark@Example.com',
                                             DEFAULT_USER_PASSWORD)
        self.assertTrue(account2 is not None)

        # Make sure both accounts are the same
        self.assertEqual(account1, account2)

    def test_authenticate_account_active(self):
        account = Account.objects.get_by_email('mark@example.com')
        # make sure account is active
        self.assertEqual(account.status, AccountStatus.ACTIVE)
        # make sure authentication succeeds
        response = self.backend.authenticate('mark@example.com',
                                             DEFAULT_USER_PASSWORD)
        self.assertEqual(response, account)

    def test_authenticate_by_token_missing_account(self):
        user = User.objects.create_user('test', 'test',
                                        password=DEFAULT_USER_PASSWORD)
        consumer = Consumer.objects.create(user=user)
        token = Token.objects.create(consumer=consumer, name='test')

        self.assertIsNone(self.backend.authenticate(token=token))

    def test_authenticate_account_inactive(self):
        account = Account.objects.get_by_email('mark@example.com')
        _status = account.status

        for status, _ in AccountStatus._get_choices():
            if status == AccountStatus.ACTIVE:
                # skip as this is tested elsewhere
                continue

            account.status = status
            account.save()

            # make sure authentication fails
            response = self.backend.authenticate('mark@example.com',
                                                 DEFAULT_USER_PASSWORD)
            self.assertEqual(response, None)

        # leave everything as it was
        account.status = _status
        account.save()

    def test_authenticate_account_no_password(self):
        account = Account.objects.get_by_email('mark@example.com')
        account.accountpassword.delete()

        response = self.backend.authenticate('mark@example.com',
                                             DEFAULT_USER_PASSWORD)

        self.assertTrue(response is None)
        account = Account.objects.get_by_email('mark@example.com')
        self.assertTrue(account is not None)

    def test_oauth_authenticate_account_active(self):
        account = Account.objects.get_by_email('mark@example.com')
        user, _ = User.objects.get_or_create(
            username=account.openid_identifier)
        consumer, created = Consumer.objects.get_or_create(user=user)
        token = account.create_oauth_token('new-token')
        oauth_token = token.oauth_token()

        # make sure the account is active
        self.assertTrue(account.status, AccountStatus.ACTIVE)

        # make sure authentication succeeds
        response = oauth_authenticate(consumer, oauth_token, None)
        self.assertEqual(response, account)

    def test_oauth_authenticate_account_inactive(self):
        account = Account.objects.get_by_email('mark@example.com')
        _status = account.status
        user, _ = User.objects.get_or_create(
            username=account.openid_identifier)

        consumer, created = Consumer.objects.get_or_create(user=user)
        token = account.create_oauth_token('new-token')
        oauth_token = token.oauth_token()

        for status, _ in AccountStatus._get_choices():
            if status == AccountStatus.ACTIVE:
                # skip as this is tested elsewhere
                continue

            account.status = status
            account.save()

            # make sure authentication fails
            response = oauth_authenticate(consumer, oauth_token, None)
            self.assertEqual(response, None)

        # leave everything as it was
        account.status = _status
        account.save()

        if created:
            consumer.delete()

    def test_oauth_authenticate_stolen_token(self):
        victim_account = Account.objects.get_by_email('mark@example.com')
        token = victim_account.create_oauth_token('new-token')
        oauth_token = token.oauth_token()

        malicious_account = Account.objects.get_by_email('test@canonical.com')
        malicious_user, _ = User.objects.get_or_create(
            username=malicious_account.openid_identifier)
        consumer, created = Consumer.objects.get_or_create(user=malicious_user)

        # make sure the accounts are active
        self.assertTrue(victim_account.status, AccountStatus.ACTIVE)
        self.assertTrue(malicious_account.status, AccountStatus.ACTIVE)

        # make sure authentication succeeds
        response = oauth_authenticate(consumer, oauth_token, None)
        self.assertFalse(response)


class SSOOAuthAuthenticationTestCase(SSOBaseTestCase):

    def setUp(self):
        super(SSOOAuthAuthenticationTestCase, self).setUp()
        self.auth = SSOOAuthAuthentication()
        # create a valid request
        self.request = Mock()
        self.request.META = {}
        self.request.REQUEST = {
            'oauth_consumer_key': '',
            'oauth_token': '',
            'oauth_signature': '',
            'oauth_signature_method': '',
            'oauth_timestamp': '',
            'oauth_nonce': '',
        }

    def test_is_authenticated_invalid_request(self):
        mock_is_valid_request = Mock(return_value=False)
        with patch.object(self.auth, 'is_valid_request',
                          mock_is_valid_request):
            self.assertEqual(self.auth.is_authenticated(self.request), False)

    @patch('sys.stdout')
    def test_is_authenticated_piston_oauth_error(self, sys_mock):
        mock_validate_token = Mock(side_effect=PistonOAuthError)
        with patch.object(self.auth, 'validate_token', mock_validate_token):
            self.assertEqual(self.auth.is_authenticated(self.request), False)

    def test_is_authenticated_no_consumer_token(self):
        consumer, token, params = None, None, None
        mock_validate_token = Mock(return_value=(consumer, token, params))
        # authentication fails as there is no consumer and token in the request
        with patch.object(self.auth, 'validate_token', mock_validate_token):
            self.assertEqual(self.auth.is_authenticated(self.request), False)

    @patch('identityprovider.auth.Account.objects.active_by_openid')
    def test_is_authenticated_inactive_account(self, mock_account_get):
        mock_account_get.return_value = None
        consumer, token, params = Mock(), Mock(), None
        # make sure validate_token returns a consumer and a token
        mock_validate_token = Mock(return_value=(consumer, token, params))
        with patch.object(self.auth, 'validate_token', mock_validate_token):
            self.assertEqual(self.auth.is_authenticated(self.request), False)

    @patch('identityprovider.auth.Account.objects.active_by_openid')
    def test_is_authenticated(self, mock_account_get):
        mock_account = Mock()
        mock_account_get.return_value = mock_account
        mock_token = Mock()
        mock_token.consumer.id = 'foo'
        consumer, params = Mock(), None
        # make sure validate_token returns a consumer and a token
        mock_validate_token = Mock(return_value=(consumer, mock_token, params))
        with patch.object(self.auth, 'validate_token', mock_validate_token):
            response = self.auth.is_authenticated(self.request)

        self.assertEqual(response, True)
        self.assertEqual(self.request.user, mock_account)
        self.assertEqual(self.request.throttle_extra, 'foo')

    def test_challenge(self):
        auth = SSOOAuthAuthentication(realm='foo')
        response = auth.challenge()
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.content, 'Authorization Required')
        self.assertEqual(response['WWW-Authenticate'], 'OAuth realm="foo"')
