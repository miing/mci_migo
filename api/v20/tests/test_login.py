from datetime import datetime
from django.utils import simplejson as json

from django.core.urlresolvers import reverse

from mock import (
    Mock,
    call as mock_call,
    patch,
)

from identityprovider.login import (
    AuthenticationError,
    AccountDeactivated,
    AccountSuspended,
    EmailInvalidated,
)
from identityprovider.tests.utils import (
    SSOBaseTestCase,
    SSOBaseUnittestTestCase,
)

from api.v20 import handlers
from api.v20.tests.utils import call
from api.v20.utils import ApiOAuthAuthentication


handler = handlers.AccountLoginHandler()
API_URL = reverse('api-login')
API_DATA = dict(
    email='foo@bar.com', password='foobar', token_name='token_name')


class LoginHandlerTestCase(SSOBaseUnittestTestCase):

    def test_login_required_parameters(self):
        response, json_body = call(handler.create, API_URL, {})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json_body, {
            'code': 'INVALID_DATA',
            'extra': {
                'email': 'Field required', 'password': 'Field required',
                'token_name': 'Field required'
            },
            'message': 'Invalid request data'})

    def test_account_suspended(self):
        self.assert_failed_login('ACCOUNT_SUSPENDED', AccountSuspended)

    def test_account_deactivated(self):
        self.assert_failed_login('ACCOUNT_DEACTIVATED', AccountDeactivated)

    def test_failed_login(self):
        self.assert_failed_login('INVALID_CREDENTIALS', AuthenticationError)

    def test_email_invalidated(self):
        self.assert_failed_login('EMAIL_INVALIDATED', EmailInvalidated)

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

    def test_login(self):
        now = datetime.utcnow()
        with patch('api.v20.handlers.authenticate_user') as mock_authenticate:
            mock_token = Mock()
            mock_token.consumer.key = 'consumer-key'
            mock_token.consumer.secret = 'consumer-secret'
            mock_token.token = 'token-key'
            mock_token.token_secret = 'token-secret'
            mock_token.created_at = now
            mock_token.updated_at = now

            mock_account = mock_authenticate.return_value
            mock_account.twofactor_required = False
            mock_account.openid_identifier = 'some-openid'
            mock_account.get_or_create_oauth_token.return_value = (mock_token,
                                                                   True)

            response, json_body = call(handler.create, API_URL, API_DATA)

        self.assertEqual(response.status_code, 201)
        expected_calls = (
            mock_call('foo@bar.com', 'foobar')
            .get_or_create_oauth_token('token_name')
            .call_list()
        )
        self.assertEqual(mock_authenticate.mock_calls, expected_calls)

        expected_response = {
            'href': '/api/v2/tokens/oauth/token-key',
            'token_key': 'token-key',
            'token_secret': 'token-secret',
            'token_name': 'token_name',
            'consumer_key': 'consumer-key',
            'consumer_secret': 'consumer-secret',
            'date_created': now,
            'date_updated': now,
            'openid': 'some-openid',
        }
        self.assertEqual(json_body, expected_response)

    def test_twofactor_required(self):
        with patch('api.v20.handlers.authenticate_user') as mock_authenticate:
            mock_account = mock_authenticate.return_value
            mock_account.twofactor_required = True

            response, json_body = call(handler.create, API_URL, API_DATA)

        self.assertEqual(response.status_code, 401)
        self.assertEqual(json_body['code'], 'TWOFACTOR_REQUIRED')

    def test_twofactor(self):
        data = API_DATA.copy()
        data['otp'] = 'one time'

        with patch('api.v20.handlers.authenticate_user') as mock_authenticate:
            mock_account = mock_authenticate.return_value
            mock_account.get_or_create_oauth_token.return_value = (Mock(),
                                                                   True)

            with patch('api.v20.handlers.twofactor') as mock_twofactor:
                response, json_body = call(handler.create, API_URL, data)

        authenticate_device = mock_twofactor.authenticate_device

        authenticate_device.assert_called_once_with(mock_account, 'one time')
        self.assertEqual(response.status_code, 201)

    def test_twofactor_wrong_otp(self):
        data = API_DATA.copy()
        data['otp'] = 'one time'
        with patch('api.v20.handlers.authenticate_user') as mock_authenticate:
            with patch('api.v20.handlers.twofactor') as mock_twofactor:
                authenticate_device = mock_twofactor.authenticate_device
                authenticate_device.side_effect = AuthenticationError

                response, json_body = call(handler.create, API_URL, data)

        mock_account = mock_authenticate.return_value
        authenticate_device.assert_called_once_with(mock_account, 'one time')
        self.assertEqual(response.status_code, 403)
        self.assertEqual(json_body['code'], 'TWOFACTOR_FAILURE')


class ApiOAuthAuthenticationTestCase(SSOBaseTestCase):

    def test_challenge(self):
        auth = ApiOAuthAuthentication()
        response = auth.challenge()

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response['WWW-Authenticate'], 'OAuth realm="API"')
        self.assertEqual(response['content-type'],
                         'application/json; charset=utf-8')

        content = json.loads(response.content)
        self.assertEqual(content['code'], 'INVALID_CREDENTIALS')
