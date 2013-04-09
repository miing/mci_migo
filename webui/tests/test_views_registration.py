# coding: utf-8

# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from mock import call, MagicMock

from django.conf import settings
from django.core.urlresolvers import reverse

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
    new_account,
)
from ssoclient.v2 import errors as api_errors

URL = reverse('new_account')
TESTDATA = {
    'email': 'test@test.com',
    'password': DEFAULT_USER_PASSWORD,
    'passwordconfirm': DEFAULT_USER_PASSWORD,
    'displayname': 'Foo bar',
    'accept_tos': True
}


class RegisterTestCase(SSOBaseUnittestTestCase):
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
        request = self.factory.get(URL, session=self.session, **data)
        return new_account(request, token)

    def post(self, token=None, **data):
        request = self.factory.post(URL, session=self.session, **data)
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
        response = self.post(**TESTDATA)

        self.mock_api_register.called_once_with(
            email=TESTDATA['email'],
            password=TESTDATA['password'],
            displayname=TESTDATA['displayname'],
            captcha_id=None,
            captcha_solution=None,
            create_captcha=False,
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['Location'], '/')
        self.assert_stat_calls(['success'])
        self.assertEqual(self.session['token_email'], TESTDATA['email'])

    def test_post_success_with_token(self):
        token = '12345678' * 2
        response = self.post(token=token, **TESTDATA)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response['Location'],
            reverse('server-decide', kwargs=dict(token=token))
        )

    def test_post_already_registered(self):
        exc = api_errors.AlreadyRegistered(MagicMock())
        self.mock_api_register.side_effect = exc
        response = self.post(**TESTDATA)
        self.assert_form_displayed(response, email='Invalid Email')
        self.assert_stat_calls(['error.email'])

    def test_post_captcha_required(self):
        exc = api_errors.CaptchaRequired(MagicMock())
        self.mock_api_register.side_effect = exc
        response = self.post(**TESTDATA)
        self.assert_form_displayed(response)
        self.assertEqual(response.context_data['captcha_required'], True)

    def test_post_captcha_failure(self):
        mock_response = MagicMock()
        body = {'extra': {'captcha_message': 'XXX'}}
        exc = api_errors.CaptchaFailure(mock_response, body)
        self.mock_api_register.side_effect = exc

        response = self.post(**TESTDATA)
        self.assert_form_displayed(response)
        self.assertEqual(response.context_data['captcha_required'], True)
        self.assertEqual(
            response.context_data['captcha_error'],
            '&error=XXX')
        self.assert_stat_calls(['error.captcha'])


class RegisterMessagesTestCase(SSOBaseTestCase):

    def setUp(self):
        super(RegisterMessagesTestCase, self).setUp()
        switch = switches(ALLOW_UNVERIFIED=True)
        switch.patch()
        self.addCleanup(switch.unpatch)

    def test_success_message(self):
        # use regular django test client to assert over messages
        response = self.client.post(URL, data=TESTDATA, follow=True)

        messages = list(response.context['messages'])
        self.assertEqual(len(messages), 1)
        expected = (
            ACCOUNT_CREATED,
            VERIFY_EMAIL_SENT % dict(email_to=TESTDATA['email'],
                                     email_from=settings.NOREPLY_FROM_ADDRESS),
        )
        self.assertEqual(unicode(messages[0]), ' '.join(expected))
