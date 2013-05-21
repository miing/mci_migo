# coding: utf-8

# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from mock import call, patch, MagicMock

from django.conf import settings
from django.core.urlresolvers import reverse
from django.contrib.messages.storage import default_storage

from gargoyle.testutils import switches

from identityprovider.tests.utils import (
    SSOBaseTestCase,
    SSOBaseUnittestTestCase,
    SSORequestFactory,
)
from identityprovider.tests import DEFAULT_USER_PASSWORD

from webui.views.registration import (
    ACCOUNT_CREATED,
    VERIFY_EMAIL_SENT,
    forgot_password,
    new_account,
)
from ssoclient.v2 import errors as api_errors


class RegisterTestCase(SSOBaseUnittestTestCase):
    URL = reverse('new_account')
    TESTDATA = {
        'email': 'test@test.com',
        'password': DEFAULT_USER_PASSWORD,
        'passwordconfirm': DEFAULT_USER_PASSWORD,
        'displayname': 'Foo bar',
        'accept_tos': True,
        'recaptcha_challenge_field': 'ignored',
        'recaptcha_response_field': 'ignored',
    }
    factory = SSORequestFactory()

    def setUp(self):
        super(RegisterTestCase, self).setUp()
        self.mock_authenticate = self._apply_patch(
            'webui.views.registration.auth.authenticate')
        mock_user = self.factory.create_mock_user()
        self.mock_authenticate.return_value = mock_user

        self.mock_get_api_client = self._apply_patch(
            'webui.views.registration.get_api_client'
        )
        self.mock_api_register = self.mock_get_api_client.return_value.register
        self.mock_increment = self._apply_patch(
            'webui.views.registration.stats.increment'
        )
        self.session = self.factory.FakeSession()

    def assert_stat_calls(self, keys, name='flows.new_account', rpconfig=None):
        self.assertEqual(len(keys), len(self.mock_increment.call_args_list))
        for key, actual in zip(keys, self.mock_increment.call_args_list):
            expected = call(name, key=key, rpconfig=rpconfig)
            self.assertEqual(expected, actual)

    def assert_form_displayed(self, response, **kwargs):
        self.assertEqual(
            response.template_name,
            'registration/new_account.html'
        )
        form = response.context_data['form']
        for field, value in kwargs.items():
            self.assertIn(value, form.errors[field][0])

    def get(self, token=None, **data):
        request = self.factory.get(self.URL, session=self.session, **data)
        return new_account(request, token)

    def post(self, token=None, **data):
        request = self.factory.post(self.URL, session=self.session, **data)
        request._messages = default_storage(request)
        return new_account(request, token)

    def test_get(self):
        response = self.get()
        ctx = response.context_data
        self.assertEqual(ctx['form']['email'].value(), None)
        self.assertEqual(ctx['rpconfig'], None)
        self.assertEqual(ctx['token'], None)
        self.assert_form_displayed(response)
        self.assert_stat_calls(['requested'])

    def test_get_with_email(self):
        response = self.get(email='test@test.com')
        ctx = response.context_data
        self.assertEqual(ctx['form']['email'].value(), 'test@test.com')

    @switches(OPTIONAL_CAPTCHA=False)
    def test_get_requires_captcha_old_flow(self):
        response = self.get()
        self.assertEqual(response.context_data['captcha_required'], True)

    @switches(OPTIONAL_CAPTCHA=True)
    @switches(CAPTCHA=False)
    def test_get_optional_captcha_switch_off(self):
        response = self.get()
        self.assertEqual(response.context_data['captcha_required'], False)

    @switches(OPTIONAL_CAPTCHA=True)
    @switches(CAPTCHA=True)
    def test_get_optional_captcha_switch_on(self):
        response = self.get()
        self.assertEqual(response.context_data['captcha_required'], True)

    def test_post_required_fields(self):
        response = self.post()
        self.assert_form_displayed(
            response,
            email='Required',
            password='Required',
            passwordconfirm='Required',
            displayname='Required'
        )
        self.assert_stat_calls(['error.form'])

    def test_post_invalid_data(self):
        response = self.post(
            email="111",
            password="ads",
            passwordconfirm="ads",
            displayname="foo"
        )
        self.assert_form_displayed(
            response,
            email='Invalid email',
            password='must be at least 8',
        )
        self.assert_form_displayed(response)
        self.assert_stat_calls(['error.form'])

    def test_post_invalid_data_with_token(self):
        token = '12345678' * 2
        response = self.post(token=token, email="111")
        self.assertEqual(response.context_data['token'], token)
        self.assert_form_displayed(response)
        self.assert_stat_calls(['error.form'])

    def test_post_success(self):
        response = self.post(**self.TESTDATA)

        self.mock_api_register.called_once_with(
            email=self.TESTDATA['email'],
            password=self.TESTDATA['password'],
            displayname=self.TESTDATA['displayname'],
            captcha_id=None,
            captcha_solution=None,
            create_captcha=False,
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['Location'], '/')
        self.assert_stat_calls(['success'])
        self.assertEqual(self.session['token_email'], self.TESTDATA['email'])

    def test_post_success_with_token(self):
        token = '12345678' * 2
        response = self.post(token=token, **self.TESTDATA)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response['Location'],
            reverse('server-decide', kwargs=dict(token=token))
        )

    def test_post_already_registered(self):
        exc = api_errors.AlreadyRegistered(MagicMock())
        self.mock_api_register.side_effect = exc
        response = self.post(**self.TESTDATA)
        self.assert_form_displayed(response, email='Invalid Email')
        self.assert_stat_calls(['error.email'])

    def test_post_captcha_required(self):
        exc = api_errors.CaptchaRequired(MagicMock())
        self.mock_api_register.side_effect = exc
        response = self.post(**self.TESTDATA)
        self.assert_form_displayed(response)
        self.assertEqual(response.context_data['captcha_required'], True)

    def test_post_captcha_failure(self):
        mock_response = MagicMock()
        body = {'extra': {'captcha_message': 'XXX'}}
        exc = api_errors.CaptchaFailure(mock_response, body)
        self.mock_api_register.side_effect = exc

        response = self.post(**self.TESTDATA)
        self.assert_form_displayed(response)
        self.assertEqual(response.context_data['captcha_required'], True)
        self.assertEqual(
            response.context_data['captcha_error'],
            '&error=XXX')
        self.assert_stat_calls(['error.captcha'])


class RegisterMessagesTestCase(SSOBaseTestCase):
    URL = reverse('new_account')
    TESTDATA = {
        'email': 'test@test.com',
        'password': DEFAULT_USER_PASSWORD,
        'passwordconfirm': DEFAULT_USER_PASSWORD,
        'displayname': 'Foo bar',
        'accept_tos': True,
        'recaptcha_challenge_field': 'ignored',
        'recaptcha_response_field': 'ignored',
    }

    def setUp(self):
        super(RegisterMessagesTestCase, self).setUp()
        switch = switches(ALLOW_UNVERIFIED=True)
        switch.patch()
        self.addCleanup(switch.unpatch)

    def test_success_message(self):
        # use regular django test client to assert over messages
        response = self.client.post(self.URL, data=self.TESTDATA, follow=True)

        messages = list(response.context['messages'])
        self.assertEqual(len(messages), 1)
        expected = (
            ACCOUNT_CREATED,
            VERIFY_EMAIL_SENT % dict(email_to=self.TESTDATA['email'],
                                     email_from=settings.NOREPLY_FROM_ADDRESS),
        )
        self.assertEqual(unicode(messages[0]), ' '.join(expected))


class PasswordResetRequestTestCase(SSOBaseUnittestTestCase):
    URL = reverse('forgot_password')
    TESTDATA = {
        'email': 'test@test.com',
    }
    factory = SSORequestFactory()

    def setUp(self):
        super(PasswordResetRequestTestCase, self).setUp()

        self.mock_get_api_client = self._apply_patch(
            'webui.views.registration.get_api_client'
        )
        self.mock_api_request_password_reset = (
            self.mock_get_api_client.return_value.request_password_reset)
        self.mock_increment = self._apply_patch(
            'webui.views.registration.stats.increment'
        )
        self.session = self.factory.FakeSession()

    def assert_stat_calls(self, keys, name='flows.forgot_password',
                          rpconfig=None):
        self.assertEqual(len(keys), len(self.mock_increment.call_args_list))
        for key, actual in zip(keys, self.mock_increment.call_args_list):
            expected = call(name, key=key, rpconfig=rpconfig)
            self.assertEqual(expected, actual)

    def assert_form_displayed(self, response, **kwargs):
        self.assertEqual(
            response.template_name,
            'registration/forgot_password.html'
        )
        form = response.context_data['form']
        for field, value in kwargs.items():
            self.assertIn(value, form.errors[field][0])

    def get(self, token=None, **data):
        request = self.factory.get(self.URL, session=self.session, **data)
        return forgot_password(request, token)

    def post(self, token=None, **data):
        request = self.factory.post(self.URL, session=self.session, **data)
        return forgot_password(request, token)

    def put(self, token=None, **data):
        request = self.factory.put(self.URL, session=self.session, **data)
        return forgot_password(request, token)

    def test_get(self):
        response = self.get()
        ctx = response.context_data
        self.assertEqual(ctx['form']['email'].value(), None)
        self.assertEqual(ctx['rpconfig'], None)
        self.assertEqual(ctx['token'], None)
        self.assert_form_displayed(response)
        self.assert_stat_calls(['requested'])

    def test_get_with_email(self):
        response = self.get(email='test@test.com')
        ctx = response.context_data
        self.assertEqual(ctx['form']['email'].value(), 'test@test.com')

    def test_post_required_fields(self):
        response = self.post()
        self.assert_form_displayed(
            response,
            email='Required',
        )
        self.assert_stat_calls(['error.form'])

    def test_post_invalid_data(self):
        response = self.post(
            email="111",
        )
        self.assert_form_displayed(
            response,
            email='Invalid email',
        )
        self.assert_form_displayed(response)
        self.assert_stat_calls(['error.form'])

    def test_post_invalid_data_with_token(self):
        token = '12345678' * 2
        response = self.post(token=token, email="111")
        self.assertEqual(response.context_data['token'], token)
        self.assert_form_displayed(response)
        self.assert_stat_calls(['error.form'])

    def test_post_success(self):
        response = self.post(**self.TESTDATA)

        self.mock_api_request_password_reset.called_once_with(
            email=self.TESTDATA['email'],
            token=None,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.session['token_email'], self.TESTDATA['email'])

    def test_post_success_with_token(self):
        token = '12345678' * 2
        response = self.post(token=token, **self.TESTDATA)

        self.mock_api_request_password_reset.called_once_with(
            email=self.TESTDATA['email'],
            token=token,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.session['token_email'], self.TESTDATA['email'])

    def test_post_email_invalidated(self):
        exc = api_errors.EmailInvalidated(MagicMock())
        self.mock_api_request_password_reset.side_effect = exc
        response = self.post(**self.TESTDATA)
        self.assertEqual(response.status_code, 200)
        self.assert_stat_calls(['error.email_invalidated'])

    def test_post_account_suspended(self):
        exc = api_errors.AccountSuspended(MagicMock())
        self.mock_api_request_password_reset.side_effect = exc
        response = self.post(**self.TESTDATA)
        self.assertEqual(response.status_code, 200)
        self.assert_stat_calls(['error.account_suspended'])

    def test_post_account_deactivated(self):
        exc = api_errors.AccountDeactivated(MagicMock())
        self.mock_api_request_password_reset.side_effect = exc
        response = self.post(**self.TESTDATA)
        self.assertEqual(response.status_code, 200)
        self.assert_stat_calls(['error.account_deactivated'])

    def test_post_can_not_reset_password(self):
        exc = api_errors.CanNotResetPassword(MagicMock())
        self.mock_api_request_password_reset.side_effect = exc
        response = self.post(**self.TESTDATA)
        self.assertEqual(response.status_code, 200)
        self.assert_stat_calls(['error.can_not_reset_password'])

    def test_post_too_many_tokens(self):
        exc = api_errors.TooManyTokens(MagicMock())
        self.mock_api_request_password_reset.side_effect = exc
        response = self.post(**self.TESTDATA)
        self.assertEqual(response.status_code, 200)
        self.assert_stat_calls(['error.too_many_tokens'])

    def test_post_captcha_required(self):
        exc = api_errors.CaptchaRequired(MagicMock())
        self.mock_api_request_password_reset.side_effect = exc
        response = self.post(**self.TESTDATA)
        self.assertEqual(response.status_code, 200)
        self.assert_stat_calls(['error.captcha'])

    def test_post_captcha_failure(self):
        mock_response = MagicMock()
        body = {'extra': {'captcha_message': 'XXX'}}
        exc = api_errors.CaptchaFailure(mock_response, body)
        self.mock_api_request_password_reset.side_effect = exc

        response = self.post(**self.TESTDATA)
        self.assertEqual(response.status_code, 200)
        self.assert_stat_calls(['error.captcha'])

    def test_brand_ubuntu(self):
        name = 'webui.views.registration.get_current_brand'
        with patch(name) as mock_get_current_brand:
            mock_get_current_brand.return_value = 'ubuntu'
            response = self.post(**self.TESTDATA)

        self.mock_api_request_password_reset.called_once_with(
            email=self.TESTDATA['email'],
            token=None,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.session['token_email'], self.TESTDATA['email'])
        self.assertEqual(response.context_data['email_heading'],
                         'Forgotten your password?')

    def test_brand_ubuntuone(self):
        name = 'webui.views.registration.get_current_brand'
        with patch(name) as mock_get_current_brand:
            mock_get_current_brand.return_value = 'ubuntuone'
            response = self.post(**self.TESTDATA)

        self.mock_api_request_password_reset.called_once_with(
            email=self.TESTDATA['email'],
            token=None,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.session['token_email'], self.TESTDATA['email'])
        self.assertEqual(response.context_data['email_heading'],
                         'Reset password')

    def test_method_not_allowed(self):
        response = self.put(**self.TESTDATA)
        self.assertEqual(response.status_code, 405)
