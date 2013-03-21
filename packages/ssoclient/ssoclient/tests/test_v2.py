import unittest

from mock import (
    MagicMock,
    patch,
)

from ssoclient.v2.client import api_exception
from ssoclient.v2.http import ApiException, ApiSession, ServerError
from ssoclient.v2 import errors, V2ApiClient


REQUEST = 'ssoclient.v2.http.requests.Session.request'


class ApiSessionTestCase(unittest.TestCase):

    @patch(REQUEST)
    def test_api_session_post_raises(self, mock_request):
        mock_request.return_value = MagicMock(status_code=500)
        api = ApiSession('http://foo.com')
        with self.assertRaises(ServerError):
            api.post('/foo', data=dict(x=1))

    @patch(REQUEST)
    def test_api_session_post(self, mock_request):
        mock_request.return_value = MagicMock(status_code=200)

        api = ApiSession('http://foo.com')
        api.post('/foo', data=dict(x=1))
        mock_request.assert_called_one_with(
            'POST',
            'http://foo.com/foo',
            data={'x': 1}
        )

    @patch(REQUEST)
    def test_api_session_get(self, mock_request):
        mock_request.return_value = MagicMock(status_code=200)

        api = ApiSession('http://foo.com')
        api.get('/foo', params=dict(x=1))
        mock_request.request.assert_called_one_with(
            'POST',
            'http://foo.com/foo',
            params={'x': 1}
        )


def mock_response(status_code, **kwargs):
    response = MagicMock(status_code=status_code)
    response.json.return_value = kwargs
    return response


class ApiExceptionTestCase(unittest.TestCase):

    class SomeException(errors.ApiException):
        error_code = "SOME_CODE"

    @api_exception(SomeException)
    def do_test(self, response):
        return response

    def test_api_exception_raises(self):
        response = mock_response(400, code="SOME_CODE")
        with self.assertRaises(self.SomeException):
            self.do_test(response)

    def test_api_exception_bad_error(self):
        response = mock_response(400)
        with self.assertRaises(errors.ApiException):
            self.do_test(response)

    def test_api_exception_returns(self):
        response = mock_response(200)
        result = self.do_test(response)
        self.assertEqual(result, response)


class V2ClientApiTestCase(unittest.TestCase):

    def setUp(self):
        super(V2ClientApiTestCase, self).setUp()
        self.client = V2ApiClient('http://foo.com')


class LoginV2ClientApiTestCase(V2ClientApiTestCase):

    def assert_invalid_response(self, status_code, ExceptionClass):
        # Test the client can handle an error response that doesn't have
        # a json body - ideally our server will never send these
        response = mock_response(status_code)
        response.json.side_effect = ValueError
        response.text = 'some error message'

        with patch(REQUEST, return_value=response):
            with self.assertRaises(ExceptionClass) as ctx:
                self.client.login(email='blah')

        if status_code >= 500:
            self.assertIn('some error message', str(ctx.exception))

    @patch(REQUEST, return_value=mock_response(400, code="INVALID_DATA"))
    def test_register_invalid_data(self, mock_request):
        with self.assertRaises(errors.InvalidData):
            self.client.register(email='blah')

    @patch(REQUEST, return_value=mock_response(401, code="CAPTCHA_REQUIRED"))
    def test_register_captcha_required(self, mock_request):
        with self.assertRaises(errors.CaptchaRequired):
            self.client.register(email='blah')

    @patch(REQUEST, return_value=mock_response(403, code="CAPTCHA_FAILURE"))
    def test_register_captcha_failed(self, mock_request):
        with self.assertRaises(errors.CaptchaFailure):
            self.client.register(email='blah')

    @patch(REQUEST, return_value=mock_response(409, code="ALREADY_REGISTERED"))
    def test_register_already_registered(self, mock_request):
        with self.assertRaises(errors.AlreadyRegistered):
            self.client.register(email='blah')

    @patch(REQUEST, return_value=mock_response(201))
    def test_register_success(self, mock_request):
        self.client.register(email='blah')
        args = mock_request.call_args[0]
        self.assertEqual(args, ('POST', 'http://foo.com/accounts'))

    def test_invalid_response_500(self):
        self.assert_invalid_response(500, ServerError)

    def test_invalid_response_400(self):
        self.assert_invalid_response(400, ApiException)


class RegisterV2ClientApiTestCase(V2ClientApiTestCase):

    @patch(REQUEST, return_value=mock_response(400, code="INVALID_DATA"))
    def test_login_invalid_data(self, mock_request):
        with self.assertRaises(errors.InvalidData):
            self.client.login(email='blah')

    @patch(REQUEST, return_value=mock_response(401, code="ACCOUNT_SUSPENDED"))
    def test_login_account_suspended(self, mock_request):
        with self.assertRaises(errors.AccountSuspended):
            self.client.login(email='blah')

    @patch(REQUEST, return_value=mock_response(
        401,
        code="ACCOUNT_DEACTIVATED"
    ))
    def test_login_account_deactivated(self, mock_request):
        with self.assertRaises(errors.AccountDeactivated):
            self.client.login(email='blah')

    @patch(REQUEST, return_value=mock_response(
        400, code="INVALID_CREDENTIALS"
    ))
    def test_login_invalid_credentials(self, mock_request):
        with self.assertRaises(errors.InvalidCredentials):
            self.client.login(email='blah')


class PasswordResetV2ClientApiTestCase(V2ClientApiTestCase):

    @patch(REQUEST, return_value=mock_response(201))
    def test_request_password_reset(self, mock_request):
        response = self.client.request_password_reset('foo@foo.com')
        self.assertEqual(response.status_code, 201)
        self.assertEqual(mock_request.call_args, [
            ('POST', 'http://foo.com/tokens/password'),
            {'headers': {'Content-Type': 'application/json'},
             'data': '{"email": "foo@foo.com"}'},
        ])

    @patch(REQUEST, return_value=mock_response(400, code="INVALID_DATA"))
    def test_request_password_reset_without_email(self, mock_request):
        with self.assertRaises(errors.InvalidData):
            self.client.request_password_reset(None)

    @patch(REQUEST, return_value=mock_response(400, code="INVALID_DATA"))
    def test_request_password_reset_with_empty_email(self, mock_request):
        with self.assertRaises(errors.InvalidData):
            self.client.request_password_reset('')

    @patch(REQUEST, return_value=mock_response(403, code="ACCOUNT_SUSPENDED"))
    def test_request_password_reset_for_suspended_account(self, mock_request):
        with self.assertRaises(errors.AccountSuspended):
            self.client.request_password_reset('foo@foo.com')

    @patch(REQUEST, return_value=mock_response(
        403, code="ACCOUNT_DEACTIVATED"))
    def test_request_password_reset_for_deactivated_account(self,
                                                            mock_request):
        with self.assertRaises(errors.AccountDeactivated):
            self.client.request_password_reset('foo@foo.com')

    @patch(REQUEST, return_value=mock_response(
        403, code="RESOURCE_NOT_FOUND"))
    def test_request_password_reset_with_invalid_email(self, mock_request):
        with self.assertRaises(errors.ResourceNotFound):
            self.client.request_password_reset('foo@foo.com')

    @patch(REQUEST, return_value=mock_response(
        403, code="CAN_NOT_RESET_PASSWORD"))
    def test_request_password_reset_not_allowed(self, mock_request):
        with self.assertRaises(errors.CanNotResetPassword):
            self.client.request_password_reset('foo@foo.com')


class AccountDetailsV2ClientApiTestCase(V2ClientApiTestCase):

    @patch(REQUEST, return_value=mock_response(200))
    def test_account_details(self, mock_request):
        token = dict(
            consumer_key='consumer_key',
            consumer_secret='consumer_secret',
            token_key='token_key',
            token_secret='token_secret',
        )
        with patch('ssoclient.v2.client.OAuth1') as mock_oauth:
            response = self.client.account_details('some_openid', token)

        mock_oauth.assert_called_once_with(
            'consumer_key', 'consumer_secret', 'token_key', 'token_secret'
        )
        self.assertTrue(all(isinstance(val, unicode) for
                            val in mock_oauth.call_args[0]))

        oauth1 = mock_oauth.return_value
        mock_request.assert_called_once_with(
            'GET', 'http://foo.com/accounts/some_openid', auth=oauth1,
            headers={}, allow_redirects=True,
        )

        # The response is mocked - so this test just confirms that the
        # account_details method "does the right thing" and returns our mock
        # repsonse
        self.assertEqual(response.status_code, 200)

    @patch(REQUEST, return_value=mock_response(200))
    def test_account_details_anonymous(self, mock_request):
        response = self.client.account_details('some_openid')
        mock_request.assert_called_once_with(
            'GET', 'http://foo.com/accounts/some_openid', auth=None,
            headers={}, allow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)


class ValidateRequestV2ClientApiTestCase(V2ClientApiTestCase):

    @patch(REQUEST)
    def test_valid_request(self, mock_request):
        mock_request.return_value = mock_response(200, is_valid=True)
        result = self.client.validate_request(
            http_url='foo', http_method='GET', authorization='123456789')
        self.assertEqual(result.json(), {'is_valid': True})

    @patch(REQUEST)
    def test_invalid_request(self, mock_request):
        mock_request.return_value = mock_response(200, is_valid=False)
        result = self.client.validate_request(
            http_url='foo', http_method='GET', authorization='123456789')
        self.assertEqual(result.json(), {'is_valid': False})
