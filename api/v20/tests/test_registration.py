from mock import (
    MagicMock,
    NonCallableMock,
    patch,
    call as mock_call,
)

from django.core.exceptions import ValidationError
from django.core.urlresolvers import reverse
from gargoyle.testutils import switches

from u1testutils.django import patch_settings

from identityprovider.models import (
    Account,
    EmailAddress,
)
from identityprovider.tests.utils import (
    SSOBaseUnittestTestCase,
)

from api.v20 import (
    handlers,
    registration,
)
from api.v20.tests.utils import call

MODULE = 'api.v20.registration'


class RegistrationTestCase(SSOBaseUnittestTestCase):

    def setUp(self):
        super(RegistrationTestCase, self).setUp()
        self.email = self.factory.make_email_address()
        self.MockEmailAddress = self._apply_patch(MODULE, 'EmailAddress')
        self.mock_account = MagicMock(spec=Account())
        self.mock_emails = MagicMock()
        self.mock_emails.count.return_value = 0
        self.MockEmailAddress.objects.filter.return_value = self.mock_emails

    @patch(MODULE + ".send_impersonation_email")
    def test_register_already_registered_and_inactive(self, mock_send):
        self.mock_emails.count.return_value = 1
        email = MagicMock()
        email.account.is_active = False
        self.mock_emails.__getitem__.return_value = email
        with self.assertRaises(registration.EmailAlreadyRegistered):
            registration.register(self.email, "", "")
        self.assertFalse(mock_send.called)

    @patch(MODULE + ".send_impersonation_email")
    def test_register_already_registered_and_active(self, mock_send):
        self.mock_emails.count.return_value = 1
        email = MagicMock()
        email.account.is_active = True
        self.mock_emails.__getitem__.return_value = email
        with self.assertRaises(registration.EmailAlreadyRegistered):
            registration.register(self.email, "", "")
        self.assertTrue(mock_send.called)

    @patch(MODULE + ".send_new_user_email")
    @patch(MODULE + ".Account.objects.create_account")
    def test_register_success(self, mock_create_account, mock_send):
        mock_create_account.return_value = self.mock_account

        registration.register(
            self.email,
            'MySecretPassword1',
            'displayname'
        )

        mock_create_account.assert_called_once_with(
            'displayname',
            self.email,
            'MySecretPassword1',
            email_validated=False
        )
        mock_send.assert_called_once_with(
            account=self.mock_account, email=self.email)

    def test_invalid_email_and_pw(self):
        with self.assertRaises(ValidationError) as e:
            registration.register("", '', 'displayname')
            self.assertEqual(
                e.message_dict['email'][0],
                'This field cannot be blank.'
            )
            self.assertEqual(
                e.message_dict['email'][0],
                'Password must be at least 8 characters long.'
            )


class RegistrationHandlerTestCase(SSOBaseUnittestTestCase):
    handler = handlers.AccountRegistrationHandler()
    url = reverse('api-registration')

    def setUp(self):
        super(RegistrationHandlerTestCase, self).setUp()
        self.data = {
            'email': self.factory.make_email_address(),
            'password': 'asdfASDF1',
            'displayname': 'Ricardo the Magnificent'
        }
        self.mock_account = MagicMock(
            spec=Account,
            openid_identifier='abcdefg',
            preferredemail=MagicMock(email=self.data['email']),
            displayname=self.data['displayname'],
            status=20
        )
        self.mock_account.emailaddress_set.all.return_value = [
            NonCallableMock(spec=EmailAddress, email=self.data['email'])
        ]
        self.mock_register = self._apply_patch(
            'api.v20.handlers.registration.register'
        )
        self.mock_register.return_value = self.mock_account

    def test_registration_handler_invalid_data(self):
        data = {'email': 'x', 'password': 'y'}
        self.mock_register.side_effect = ValidationError({'email': 'Invalid'})
        response, json_body = call(self.handler.create, self.url, data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json_body['code'], "INVALID_DATA")
        self.assertIn("Invalid request data", json_body['message'])
        self.assertIn('email', json_body['extra'])
        self.assertNotIn('password', json_body['extra'])
        self.assertNotIn('displayname', json_body['extra'])

    def test_registration_already_registered(self):
        self.mock_register.side_effect = registration.EmailAlreadyRegistered
        response, json_body = call(self.handler.create, self.url, self.data)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(json_body['code'], "ALREADY_REGISTERED")
        self.assertIn("already registered", json_body['message'])
        self.assertIn('email', json_body['extra'])
        self.assertIn(self.data['email'], json_body['extra']['email'])

    def test_registration_success(self):
        response, json_body = call(self.handler.create, self.url, self.data)
        self.assertEqual(response.status_code, 201)
        self.assertIn('openid', json_body)
        self.assertIn('href', json_body)
        self.assertEqual(json_body['email'], self.data['email'])
        self.assertEqual(json_body['displayname'], self.data['displayname'])
        self.assertEqual(json_body['status'], 'Active')
        self.assertEqual(len(json_body['emails']), 1)
        self.assertIn(self.data['email'], json_body['emails'][0]['href'])

    @patch('api.v20.handlers.Captcha')
    def test_register_captcha_required(self, mock_captcha):
        captcha_data = {'captcha_id': 999, 'image_url': 'somewhere'}
        mock_captcha.new.return_value.serialize.return_value = captcha_data
        with switches(CAPTCHA=True):
            response, json_body = call(
                self.handler.create, self.url, self.data)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(json_body['code'], "CAPTCHA_REQUIRED")
        self.assertIn('A captcha challenge is required', json_body['message'])
        self.assertFalse(self.mock_register.called)
        self.assertEqual(json_body['extra'], captcha_data)

    @patch('api.v20.handlers.Captcha')
    def test_register_captcha_success(self, mock_captcha):
        mock_captcha.return_value.verify.return_value = True
        self.data['captcha_id'] = 999
        self.data['captcha_solution'] = 'foo bar'

        response, json_body = call(self.handler.create, self.url, self.data)

        self.assertEqual(response.status_code, 201)
        expected_calls = mock_call(999).verify(
            'foo bar', '127.0.0.1', self.data['email']).call_list()
        self.assertEqual(mock_captcha.mock_calls, expected_calls)

        self.assertIn('openid', json_body)
        self.assertIn('href', json_body)
        self.assertEqual(json_body['email'], self.data['email'])
        self.assertEqual(json_body['displayname'], self.data['displayname'])
        self.assertEqual(json_body['status'], 'Active')
        self.assertEqual(len(json_body['emails']), 1)
        self.assertIn(self.data['email'], json_body['emails'][0]['href'])

    @patch('api.v20.handlers.Captcha')
    def test_register_captcha_failure(self, mock_captcha):
        mock_captcha.return_value.verify.return_value = False
        self.data['captcha_id'] = 999
        self.data['captcha_solution'] = 'foo bar'

        response, json_body = call(self.handler.create, self.url, self.data)
        self.assertEqual(response.status_code, 403)
        expected_calls = mock_call(999).verify(
            'foo bar', '127.0.0.1', self.data['email']).call_list()
        self.assertEqual(mock_captcha.mock_calls, expected_calls)

        self.assertEqual(json_body['code'], "CAPTCHA_FAILURE")
        self.assertIn('Failed response to captcha challenge.',
                      json_body['message'])
        self.assertFalse(self.mock_register.called)

    OVERIDES = dict(
        DISABLE_CAPTCHA_VERIFICATION=False,
        EMAIL_WHITELIST_REGEXP_LIST=['^canonicaltest(?:\+.+)?@gmail\.com$']
    )

    @patch('identityprovider.models.captcha.Captcha._open')
    def test_register_captcha_whitelist(self, mock_open):
        self.data['email'] = 'canonicaltest@gmail.com'
        self.data['captcha_id'] = '999'
        self.data['captcha_solution'] = 'foo bar'
        with patch_settings(**self.OVERIDES):
            response, json_body = call(
                self.handler.create, self.url, self.data
            )
        self.assertTrue(self.mock_register.called)
        self.assertFalse(mock_open.called)

    @patch('identityprovider.models.captcha.Captcha._open')
    def test_register_captcha_whitelist_with_uuid(self, mock_open):
        self.data['email'] = 'canonicaltest+something@gmail.com'
        self.data['captcha_id'] = '999'
        self.data['captcha_solution'] = 'foo bar'
        with patch_settings(**self.OVERIDES):
            response, json_body = call(
                self.handler.create, self.url, self.data
            )
        self.assertTrue(self.mock_register.called)
        self.assertFalse(mock_open.called)

    @patch('identityprovider.models.captcha.Captcha._open')
    def test_register_captcha_whitelist_fail(self, mock_open):
        self.data['captcha_id'] = '999'
        self.data['captcha_solution'] = 'foo bar'
        self.data['email'] = 'notcanonicaltest@gmail.com'
        mock_open.return_value.is_error = False
        mock_open.return_value.data.return_value = 'false\nmessage'

        with patch_settings(**self.OVERIDES):
            response, json_body = call(
                self.handler.create, self.url, self.data
            )
        self.assertFalse(self.mock_register.called)
        self.assertTrue(mock_open.called)
