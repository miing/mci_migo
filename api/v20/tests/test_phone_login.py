from django.core.urlresolvers import reverse
from gargoyle.testutils import switches
from mock import patch

from identityprovider.login import (
    AuthenticationError,
    AccountDeactivated,
    AccountSuspended,
)
from identityprovider.models.emailaddress import PHONE_EMAIL_DOMAIN
from identityprovider.tests import DEFAULT_USER_PASSWORD
from identityprovider.tests.utils import (
    TeamConditionSelectiveMixin,
    SSOBaseTestCase,
)

from api.v20 import handlers
from api.v20.tests.utils import call


handler = handlers.AccountPhoneLoginHandler()
API_URL = reverse('api-login-phone')
API_DATA = dict(
    email='foo@bar.com', phone_id='tel:+1234567890',
    password='foobar', token_name='token_name')


class PhoneLoginHandlerTestCase(SSOBaseTestCase):

    def setUp(self):
        super(PhoneLoginHandlerTestCase, self).setUp()
        self.enable_flag()

    def enable_flag(self):
        # enable LOGIN_BY_PHONE globally
        switcher = switches(LOGIN_BY_PHONE=True)
        switcher.patch()
        self.addCleanup(switcher.unpatch)

    def make_account(self):
        return self.factory.make_account()

    def test_login_required_parameters(self):
        response, json_body = call(handler.create, API_URL, {})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json_body, {
            'code': 'INVALID_DATA',
            'extra': {
                'phone_id': 'Field required', 'password': 'Field required',
                'token_name': 'Field required'
            },
            'message': 'Invalid request data'})

    def test_account_suspended(self):
        self.assert_failed_login('ACCOUNT_SUSPENDED', AccountSuspended)

    def test_account_deactivated(self):
        self.assert_failed_login('ACCOUNT_DEACTIVATED', AccountDeactivated)

    def test_failed_login(self):
        self.assert_failed_login('INVALID_CREDENTIALS', AuthenticationError)

    def assert_failed_login(self, code, exception):
        status_code = 403
        if exception is AuthenticationError:
            status_code = 401

        with patch('api.v20.handlers.authenticate_user') as mock_authenticate:
            mock_authenticate.side_effect = exception
            response, json_body = call(handler.create, API_URL, API_DATA)

        self.assertEqual(response.status_code, status_code)
        mock_authenticate.assert_called_once_with('foo@bar.com', 'foobar')
        self.assertEqual(json_body['code'], code)

    def test_login_add_phone_email(self):
        account = self.make_account()
        email = account.preferredemail
        # no unverified_emails
        assert len(account.unverified_emails()) == 0

        data = {'phone_id': 'tel:+1234567890', 'email': email.email,
                'password': DEFAULT_USER_PASSWORD, 'token_name': 'token_name'}
        response, json_body = call(handler.create, API_URL, data)

        self.assertEqual(response.status_code, 201)
        token, created = account.get_or_create_oauth_token('token_name')
        expected_response = {
            "consumer_key": token.consumer.key,
            "consumer_secret": token.consumer.secret,
            "token_key": token.token,
            "token_secret": token.token_secret,
            "token_name": 'token_name',
            "date_created": token.created_at,
            "href": reverse('api-token', args=(token.token,)),
            "openid": account.openid_identifier,
        }
        # ignore date_updated
        json_body.pop('date_updated')
        # we're just retrieving an existing token
        self.assertFalse(created)
        self.assertEqual(json_body, expected_response)
        # check added phone email
        unverified_emails = account.unverified_emails()
        self.assertEqual(len(unverified_emails), 1)
        phone_email = unverified_emails[0].email
        self.assertTrue(phone_email.endswith(PHONE_EMAIL_DOMAIN))

    def test_login_without_email_or_added_phone_email(self):
        account = self.make_account()
        # no unverified_emails
        assert len(account.unverified_emails()) == 0

        data = {'phone_id': 'tel:+1234567890',
                'password': DEFAULT_USER_PASSWORD, 'token_name': 'token_name'}
        response, json_body = call(handler.create, API_URL, data)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(json_body, {
            'code': 'INVALID_DATA',
            'extra': {'phone_id': 'invalid value'},
            'message': 'Invalid request data'})

    def test_login_with_phone_email(self):
        account = self.make_account()
        email = account.preferredemail
        # no unverified_emails
        assert len(account.unverified_emails()) == 0

        # login first with email and phone id
        data = {'phone_id': 'tel:+1234567890', 'email': email.email,
                'password': DEFAULT_USER_PASSWORD, 'token_name': 'token_name'}
        response, json_body = call(handler.create, API_URL, data)
        assert response.status_code == 201

        # now we should be able to login with phone id only
        data = {'phone_id': 'tel:+1234567890',
                'password': DEFAULT_USER_PASSWORD, 'token_name': 'token_name'}
        response, json_body = call(handler.create, API_URL, data)
        self.assertEqual(response.status_code, 200)
        token, created = account.get_or_create_oauth_token('token_name')
        expected_response = {
            "consumer_key": token.consumer.key,
            "consumer_secret": token.consumer.secret,
            "token_key": token.token,
            "token_secret": token.token_secret,
            "token_name": 'token_name',
            "date_created": token.created_at,
            "href": reverse('api-token', args=(token.token,)),
            "openid": account.openid_identifier,
        }
        # ignore date_updated
        json_body.pop('date_updated')
        # we're just retrieving an existing token
        self.assertFalse(created)
        self.assertEqual(json_body, expected_response)


class PhoneLoginHandlerSelectiveTestCase(PhoneLoginHandlerTestCase,
                                         TeamConditionSelectiveMixin):

    key = 'LOGIN_BY_PHONE'
