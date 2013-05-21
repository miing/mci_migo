# coding: utf-8

# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

import re
import urllib2

from functools import partial
from urlparse import urlsplit

from mock import patch, Mock
from pyquery import PyQuery
from unittest import skipUnless

from django.conf import settings
from django.contrib.sessions.models import Session
from django.core import mail
from django.core.urlresolvers import reverse
from django.http import QueryDict, HttpResponse

from gargoyle.testutils import switches
from gargoyle import gargoyle

from openid.message import IDENTIFIER_SELECT
from u1testutils.logging import LogHandlerTestCase

from identityprovider import signed
from identityprovider.models import (
    Account,
    AuthToken,
    EmailAddress,
    OpenIDRPConfig,
    twofactor,
)
from identityprovider.models.authtoken import create_token
from identityprovider.models.captcha import Captcha
from identityprovider.models.const import AccountStatus, EmailStatus, TokenType
from identityprovider.readonly import ReadOnlyManager
from identityprovider.tests import DEFAULT_USER_PASSWORD
from identityprovider.tests.utils import (
    MockHandler,
    SSOBaseTestCase,
    patch_settings,
)
from identityprovider.utils import validate_launchpad_password
from identityprovider.views import server

from webui import decorators
from webui.views import ui


ONE_TIME_PWD_ERROR = "Please enter a 6-digit or 8-digit one-time password."
DISPLAYNAME = 'Mark Shuttleworth'


def _args_list(flow_name, key=None):
    if key is None:
        key = 'success'
    return [
        ((flow_name,), {'key': 'requested', 'rpconfig': None}),
        ((flow_name,), dict(rpconfig=None, key=key)),
    ]


class BaseTestCase(SSOBaseTestCase):

    email = 'mark@example.com'
    new_email = 'person@example.com'

    def setUp(self):
        super(BaseTestCase, self).setUp()

        p = patch('webui.views.ui.stats.increment')
        self.mock_increment = p.start()
        self.addCleanup(p.stop)

        self.data = {'email': self.email,
                     'password': DEFAULT_USER_PASSWORD}
        self.account = self.factory.make_account(**self.data)

    def post_new_account(
            self,
            email=None,
            token=None,
            follow=False,
            captcha=True):
        if email is None:
            email = self.new_email
        if token is None:
            url = reverse('new_account')
        else:
            url = reverse('new_account', kwargs=dict(token=token))
        data = {
            'displayname': DISPLAYNAME,
            'email': email,
            'password': 'Testing123',
            'passwordconfirm': 'Testing123',
            'accept_tos': True
        }
        if captcha:
            data['recaptcha_challenge_field'] = 'ignored'
            data['recaptcha_response_field'] = 'ignored'

        return self.client.post(url, data, follow=follow)

    def _token_url(self):
        token_string = self.mock_send_email.call_args[0][2]['token']
        token = AuthToken.objects.get(token=token_string)
        return token.absolute_url

    def authenticate(self):
        self.client.login(username=self.data['email'],
                          password=self.data['password'])

    def request_when_captcha_fails(self, url, data):
        class MockCaptcha(object):
            def __init__(self, *args):
                pass

            def verify(self, solution, ip_addr, email):
                self.message = 'no-challenge'
                return False

            @classmethod
            def new(cls, env):
                return cls()

        with patch.object(ui, 'Captcha', MockCaptcha):
            r = self.client.post(url, data)

        return r


class SpanishUIViewsTestCase(BaseTestCase):

    def setUp(self):
        super(SpanishUIViewsTestCase, self).setUp()
        language_code = settings.LANGUAGE_CODE
        settings.LANGUAGE_CODE = 'es'
        self.addCleanup(setattr, settings, 'LANGUAGE_CODE', language_code)

    def test_new_account_in_spanish(self):
        self.account.status = AccountStatus.ACTIVE
        self.account.save()

        r = self.post_new_account(email=self.email)

        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(mail.outbox), 1)


class UIViewsBaseTestCase(BaseTestCase):

    def setUp(self):
        super(UIViewsBaseTestCase, self).setUp()
        self.mock_send_email = self._apply_patch(
            'identityprovider.emailutils.send_branded_email'
        )


class LoginTestCase(UIViewsBaseTestCase):

    def test_login_with_unicode_email(self):
        email = u'mark@客example.com'
        password = DEFAULT_USER_PASSWORD
        Account.objects.create_account(DISPLAYNAME, email, password)
        self.data['email'] = email.encode('utf-8')
        r = self.client.post(reverse('login'), self.data)

        self.assertRedirects(r, reverse('account-index'))

    def test_login_with_unicode_password(self):
        self.data['password'] = u'test客'.encode('utf-8')
        r = self.client.post(reverse('login'), self.data)

        self.assertFormError(r, 'form', None, 'Password didn\'t match.')

    def test_login_with_next(self):
        self.data['next'] = reverse('account-edit')
        r = self.client.post(reverse('login'), self.data)
        self.assertRedirects(r, reverse('account-edit'))

    def test_login_when_account_inactive(self):
        _password = self.account.accountpassword.password

        for status, _ in AccountStatus._get_choices():
            if status == AccountStatus.ACTIVE:
                # skip as this is already tested by test_login_with_next
                continue

            self.account.status = status
            self.account.save()
            # reset password in case previous status was suspended, which
            # resets the password
            self.account.accountpassword.password = _password
            self.account.accountpassword.save()

            self.data['next'] = reverse('account-edit')
            r = self.client.post(reverse('login'), self.data)

            if status == AccountStatus.SUSPENDED:
                self.assertContains(r, 'Your account has been suspended. '
                                       'Please contact login support to '
                                       're-enable it')
            else:
                self.assertContains(r, 'Your account has been deactivated. '
                                       'To reactivate it, please reset your '
                                       'password')

    def test_login_without_next_with_token(self):
        token = 'a' * 16
        r = self.client.post(reverse('login', kwargs=dict(token=token)),
                             self.data)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r['Location'], "http://testserver/%s/" % token)

    def test_login_without_next_nor_token(self):
        r = self.client.post(reverse('login'), self.data)
        self.assertRedirects(r, reverse('account-index'))

    @switches(LOGIN_BY_PHONE=False, ALLOW_UNVERIFIED=False)
    def test_login_with_not_validated_email_not_permitted(self):
        """Preventing regression for bug 816622"""
        self.account.emailaddress_set.create(
            email="mark-2@example.com", status=EmailStatus.NEW)
        self.data['email'] = 'mark-2@example.com'
        r = self.client.post(reverse('login'), self.data)
        self.assertFormError(r, 'form', None, "Password didn't match.")

    @switches(LOGIN_BY_PHONE=False)
    def test_login_with_not_validated_email_permitted(self):
        self.account.emailaddress_set.create(
            email="mark-2@example.com", status=EmailStatus.NEW)
        with switches(ALLOW_UNVERIFIED=True):
            self.data['email'] = 'mark-2@example.com'
            r = self.client.post(reverse('login'), self.data)
        self.assertRedirects(r, reverse('account-index'))

    @patch('webui.views.ui.get_rpconfig_from_request')
    def test_login_with_unverified_email_disabled_by_rpconfig(
            self, mock_get_rpconfig):

        rpconfig = OpenIDRPConfig(trust_root='http://localhost/foo',
                                  allow_unverified=False)
        mock_get_rpconfig.return_value = rpconfig

        # make account unverified
        self.account.emailaddress_set.all().update(status=EmailStatus.NEW)
        assert not self.account.is_verified
        self.data['email'] = 'mark@example.com'

        # use a token in the request to fake an openid request
        token = 'a' * 16
        with switches(ALLOW_UNVERIFIED=True, LOGIN_BY_PHONE=False):
            r = self.client.post(reverse('login', kwargs={'token': token}),
                                 self.data)

        self.assertFormError(r, 'form', None, "Password didn't match.")

    def test_login_with_invalidated_email_error(self):
        email_obj = EmailAddress.objects.get(email="mark@example.com")
        email_obj.invalidate()

        with switches(ALLOW_UNVERIFIED=True):
            r = self.client.post(reverse('login'), self.data)
        self.assertFormError(
            r, 'form', None,
            "This email address has been invalidated. "
            "Please contact login support.")

    def test_login_with_invalidated_email_error_when_email_readded(self):
        email_obj = EmailAddress.objects.get(email="mark@example.com")
        email_obj.invalidate()

        self.factory.make_account(email=self.email, password="password")
        with switches(ALLOW_UNVERIFIED=True):
            r = self.client.post(reverse('login'), self.data)
        self.assertFormError(
            r, 'form', None,
            "Password didn't match.")

    def test_suspended_account_should_require_a_password_reset(self):
        """Checking regression in #620462."""
        self.account.suspend()

        # Try to log in using just suspended account
        response = self.client.post(
            reverse('login'), data=dict(email=self.email,
                                        password=DEFAULT_USER_PASSWORD))
        # This should produce an error
        suspended = ('<span class="error">Your account has been suspended. '
                     'Please contact login support to re-enable it</span>')
        self.assertContains(response, suspended)

        # re-enable the account
        self.account.status = AccountStatus.ACTIVE
        self.account.save()

        response = self.client.post(
            reverse('login'), data=dict(email=self.email,
                                        password=DEFAULT_USER_PASSWORD))

        # If the url is still the same, that means that the log in was
        # unsuccessful.
        self.assertContains(
            response,
            '<span class="error">Password didn&#39;t match.</span>')

    def test_includes_create_account_form_for_u1_brand(self):
        with patch.multiple(settings, BRAND='ubuntu'):
            with switches(BRAND_UBUNTUONE=True):
                r = self.client.get(reverse('login'))

        self.assertIn('create_account_form', r.context)

    def test_create_account_form_not_included_for_ubuntu_brand(self):
        with patch.multiple(settings, BRAND='ubuntu'):
            with switches(BRAND_UBUNTUONE=False):
                r = self.client.get(reverse('login'))

        self.assertNotIn('create_account_form', r.context)


class LogoutTestCase(UIViewsBaseTestCase):

    def test_logout(self):
        self.authenticate()
        r = self.client.get(reverse('logout'))
        self.assertTemplateUsed(r, 'registration/logout.html')

    def test_logout_preserve_token(self):
        self.authenticate()
        token = 'a' * 16
        # This strange dance with session is necessary to overcome way in which
        # test.Client returns session (recreating it on every Client.session
        # access)
        session = self.client.session
        request = {'openid.mode': 'checkid_setup',
                   'openid.trust_root': 'http://localhost/',
                   'openid.return_to': 'http://localhost/',
                   'openid.identity': IDENTIFIER_SELECT}
        openid_server = server._get_openid_server()
        orequest = openid_server.decodeRequest(request)
        expected = signed.dumps(orequest, settings.SECRET_KEY)
        session[token] = expected
        session.save()

        self.client.get(reverse('logout', kwargs=dict(token=token)))
        self.assertEqual(expected, self.client.session.get(token))

    def test_logout_displays_ga_snippet(self):
        self.authenticate()
        rpconfig = OpenIDRPConfig.objects.create(
            trust_root='https://www.example.com/openid/',
            ga_snippet='[["_setAccount", "12345"]]')

        token = self._assign_token_to_rpconfig(rpconfig)
        response = self.client.get(reverse('logout', kwargs=dict(token=token)))
        self.assertContains(response, "_gaq.push(['_setAccount', '12345']);")

    def test_claim_token_for_password_recovery_no_preferredemail(self):
        """Prevent password reset for unverified emails."""
        for email_obj in self.account.emailaddress_set.all():
            email_obj.status = EmailStatus.NEW
            email_obj.save()

        self.client.post(reverse('forgot_password'), {'email': self.email})

        # we send an email anyway despite there not being a validated email
        self.assertEqual(self.mock_send_email.call_count, 1)


class EnterTokenTestCase(UIViewsBaseTestCase):

    def setUp(self):
        super(EnterTokenTestCase, self).setUp()
        self.data = {'email': self.email}

    def test_enter_unexisting_token(self):
        r = self.client.post(reverse('enter_token'), {
            'email': 'fake@example.com',
            'confirmation_code': '0'})
        self.assertContains(r, 'Unknown confirmation code')

    def test_claim_unexisting_token(self):
        r = self.client.get(
            reverse('claim_token', kwargs=dict(authtoken=0)), self.data)
        self.assertEqual(r.status_code, 404)

    def test_claim_token_for_unexisting_token_type(self):
        token = self.factory.make_authtoken(email='fake@example.com')
        token.token_type = 9999
        token.save()
        r = self.client.get(
            reverse('claim_token', kwargs=dict(authtoken=token.token)),
            self.data)
        self.assertEqual(r.status_code, 404)

    def test_claim_consumed_token(self):
        self.client.post(reverse('forgot_password'), {'email': self.email})
        url = self._token_url()

        pwd = 'Password1'
        r = self.client.post(url, {'password': pwd, 'passwordconfirm': pwd})
        self.assertRedirects(r, reverse('account-index'))

        self.client.cookies.clear()

        pwd = 'Password2'
        r = self.client.post(url, {'password': pwd, 'passwordconfirm': pwd})
        self.assertRedirects(r, reverse('bad_token'))

    def test_token_form_validation(self):
        r = self.client.post(reverse('enter_token'))
        self.assertContains(r, '<span class="error"')


class NewEmailTestCase(UIViewsBaseTestCase):

    def test_config_email(self):
        self.authenticate()

        redirection_url = "http://example.com/foo/bar/baz"
        token = self.factory.make_authtoken(
            token_type=TokenType.VALIDATEEMAIL, email=self.email,
            redirection_url=redirection_url)

        r = self.client.post(token.absolute_url, {'post': 'yes'})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r['Location'], redirection_url)

    def test_config_email_no_redirection_url(self):
        self.authenticate()

        token = self.factory.make_authtoken(
            token_type=TokenType.VALIDATEEMAIL, email=self.email,
            redirection_url=None)

        r = self.client.post(token.absolute_url, {'post': 'yes'})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(
            r['Location'],
            'http://testserver' + reverse('account-index')
        )

    def test_bad_token(self):
        r = self.client.get(reverse('bad_token'))
        self.assertEqual(r.status_code, 200)

    def test_non_field_errors_is_not_in_html(self):
        r = self.client.post(reverse('enter_token'), {
            'email': 'fake@example.com',
            'confirmation_code': '0'})
        # non field error section immediately follows a <p>
        self.assertNotContains(r, '<p><span class="error"')
        self.assertContains(r, '<span class="error"')

    def test_logout_to_confirm(self):
        r = self.client.get(reverse('logout_to_confirm'))
        self.assertEqual(r.status_code, 200)

    def test_logout_to_confirm_use_request_context(self):
        response = self.client.get(reverse('logout_to_confirm'))
        msg = ('You have attempted to confirm an account while logged in as '
               'someone else.')
        self.assertContains(response, msg)


class ConfirmAccountTestCase(LogHandlerTestCase, UIViewsBaseTestCase):

    def test_confirm_account_while_logged_in(self):
        token = self.factory.make_authtoken(
            token_type=TokenType.NEWPERSONLESSACCOUNT, email='me@example.com')
        self.authenticate()
        r = self.client.get(token.absolute_url)
        self.assertRedirects(r, reverse('logout_to_confirm'))

    @switches(ALLOW_UNVERIFIED=False)
    def test_confirm_account_redirect_to_decide_token_error(self):
        # get a valid session
        token1 = 'a' * 16
        r = self.post_new_account(token=token1)
        self.assertEqual(r.status_code, 200)

        # claim token
        r = self.client.post(self._token_url(),
                             {'displayname': 'Person', 'password': 'P4ssw0rd',
                              'passwordconfirm': 'P4ssw0rd',
                              'accept_tos': True})
        self.assertRedirects(
            r, reverse('server-decide', kwargs=dict(token=token1)))

    @switches(ALLOW_UNVERIFIED=False)
    def test_confirm_account_redirect_to_decide_token(self):
        # get a valid session
        token1 = create_token(16)
        r = self.post_new_account(token=token1)
        self.assertEqual(r.status_code, 200)

        # claim token
        r = self.client.post(self._token_url(),
                             {'displayname': 'Person', 'password': 'P4ssw0rd',
                              'passwordconfirm': 'P4ssw0rd',
                              'accept_tos': True})
        self.assertRedirects(
            r, reverse('server-decide', kwargs=dict(token=token1)))

    @switches(ALLOW_UNVERIFIED=False)
    def test_confirm_account_redirect_to_decide_with_rpconfig(self):
        token = create_token(16)
        r = self.post_new_account(token=token)
        self.assertEqual(r.status_code, 200)
        # create rpconfig
        rpconfig = OpenIDRPConfig.objects.create(
            trust_root='http://localhost/')
        self._assign_token_to_rpconfig(rpconfig, token=token)

        # claim token
        r = self.client.post(self._token_url(),
                             {'displayname': 'Person', 'password': 'P4ssw0rd',
                              'passwordconfirm': 'P4ssw0rd',
                              'accept_tos': True})
        self.assertRedirects(
            r, reverse('server-decide', kwargs=dict(token=token)))

        # verify account created
        account = Account.objects.get(pk=self.client.session['_auth_user_id'])
        self.assertEqual(account.creation_rationale,
                         rpconfig.creation_rationale)

    def test_confirm_account_without_redirection_url(self):
        token = self.factory.make_authtoken(
            token_type=TokenType.NEWPERSONLESSACCOUNT,
            email='me@example.com', displayname='Me', password='password')
        self.assertEqual(token.redirection_url, None)

        # confirm account
        r = self.client.post(token.absolute_url, {'post': 'yes'})
        self.assertRedirects(r, reverse('account-index'))

    def test_confirm_account_invalid_form(self):
        token1 = create_token(16)
        r = self.client.post(reverse('new_account', kwargs=dict(token=token1)))
        self.assertTemplateUsed(r, 'registration/new_account.html')
        self.assertFormError(r, 'form', 'displayname', 'Required field.')

    def test_confirm_account_set_preferredemail_with_existing_account(self):
        account = Account.objects.create_account(
            'Test User', 'test@test.com', 'encrypted',
            password_encrypted=True, email_validated=False)
        self.factory.make_authtoken(
            token_type=TokenType.NEWPERSONLESSACCOUNT, email='test@test.com',
            displayname='Test User', password='encrypted')

        if gargoyle.is_active('ALLOW_UNVERIFIED'):
            self.assertEqual(account.preferredemail.email, 'test@test.com')
        else:
            self.assertEqual(account.preferredemail, None)

        unverified = account.unverified_emails()
        self.assertEqual([emailaddress.email for emailaddress in unverified],
                         ['test@test.com'])

        # confirm account
        token = AuthToken.objects.get(
            email='test@test.com', token_type=TokenType.NEWPERSONLESSACCOUNT)
        self.client.post(token.absolute_url, {'post': 'yes'})

        # refresh the account object
        account = Account.objects.get(id=account.id)

        self.assertEqual(account.preferredemail.email, 'test@test.com')
        unverified = account.unverified_emails()
        self.assertEqual([emailaddress.email for emailaddress in unverified],
                         [])

    @patch('identityprovider.emailutils.send_new_user_email')
    @patch('webui.views.ui.encrypt_launchpad_password')
    @switches(ALLOW_UNVERIFIED=False)
    def test_new_user_email_sent(self, mock_encrypt, mock_send):
        mock_encrypt.return_value = 'password'
        email = 'foo@example.com'
        account = Account.objects.get_by_email(email)
        assert account is None

        self.post_new_account(email=email)

        mock_send.assert_called_once_with(
            account=None, email=email,
            redirection_url=reverse('account-index'),
            displayname=DISPLAYNAME, platform='web', password='password')
        mock_encrypt.assert_called_once_with('Testing123')

    @patch('identityprovider.emailutils.send_impersonation_email')
    @switches(ALLOW_UNVERIFIED=False)
    def test_impersonation_warning_email_sent(self, mock_send):
        self.factory.make_email_for_account(
            self.account, email=self.new_email, status=EmailStatus.NEW)

        account = Account.objects.get_by_email(self.new_email)
        assert account.is_active
        assert account.preferredemail.email == self.email

        self.post_new_account(email=self.new_email)

        # ensure the preferredemail from the original account is used
        mock_send.assert_called_once_with(self.email)

    @patch('identityprovider.emailutils.send_impersonation_email')
    @switches(ALLOW_UNVERIFIED=False)
    def test_impersonation_warning_email_for_unverified_account(self,
                                                                mock_send):
        # make sure account has no preferred email
        self.account.emailaddress_set.all().update(status=EmailStatus.NEW)
        assert self.account.is_active
        assert self.account.preferredemail is None

        mock_is_enabled = Mock(return_value=True)
        with patch.object(self.root_logger, 'isEnabledFor', mock_is_enabled):
            with patch('webui.views.ui.logger', self.root_logger):
                self.post_new_account(email=self.email)

        self.assertFalse(mock_send.called)
        self.assertLogLevelContains(
            'DEBUG', "In view 'new_account' email was not "
            "sent out because account '%s' has no preferred email." %
            self.account.displayname)


class ForgotPasswordTestCase(UIViewsBaseTestCase):

    def test_forgot_password_includes_rp_analytics(self):
        rpconfig = OpenIDRPConfig.objects.create(
            trust_root='http://example.com/',
            ga_snippet='[["_setAccount", "12345"]]')
        token = self._assign_token_to_rpconfig(rpconfig)
        response = self.client.get(
            reverse('forgot_password', kwargs=dict(token=token)))
        self.assertContains(response, "_gaq.push(['_setAccount', '12345']);")

    def test_forgot_password_email_when_account_active(self):
        self.client.post(reverse('forgot_password'), {'email': self.email})

        self.assertEqual(self.mock_send_email.call_count, 1)

    def test_forgot_password_email_when_account_deactivated(self):
        """ Deactivated accounts can be reactivated using the reset password
        functionality. Bug #556878 """
        # make sure the account is deactivated
        self.account.status = AccountStatus.DEACTIVATED
        self.account.save()

        self.client.post(reverse('forgot_password'), {'email': self.email})

        self.assertEqual(self.mock_send_email.call_count, 1)
        self.assertEqual(self.account.preferredemail.email, self.email)

    def test_forgot_password_email_when_account_noaccount(self):
        # make sure the account is deactivated
        self.account.status = AccountStatus.NOACCOUNT
        self.account.save()

        self.client.post(reverse('forgot_password'), {'email': self.email})

        self.assertEqual(self.mock_send_email.call_count, 1)
        self.assertEqual(self.account.preferredemail.email, self.email)

    def test_forgot_password_email_when_account_suspended(self):
        # make sure the account is suspended
        self.account.suspend()

        self.client.post(reverse('forgot_password'), {'email': self.email})

        self.assertEqual(self.mock_send_email.call_count, 0)

    def test_forgot_password_invalid_form(self):
        r = self.client.post(reverse('forgot_password'))
        self.assertEqual(r.status_code, 200)
        self.assertTemplateUsed(r, 'registration/forgot_password.html')
        self.assertFormError(r, 'form', 'email', 'Required field.')

    def test_forgot_password_with_token(self):
        token1 = create_token(16)
        self.client.post(
            reverse('forgot_password', kwargs=dict(token=token1)),
            {'email': self.email}
        )
        # should be only one
        auth_token = AuthToken.objects.get(
            email=self.email, token_type=TokenType.PASSWORDRECOVERY)
        self.assertEqual(auth_token.redirection_url,
                         reverse('server-decide', kwargs=dict(token=token1)))

    def test_reset_password_when_account_active(self):
        r = self.client.post(reverse('forgot_password'), {'email': self.email})

        # make sure the account is active
        self.account.status = AccountStatus.ACTIVE
        self.account.save()

        # confirm account
        data = {'password': 'Password1', 'passwordconfirm': 'Password1'}
        r = self.client.post(self._token_url(), data)
        self.assertRedirects(r, reverse('account-index'))

    def test_reset_password_with_lowered_password_requirements(self):
        r = self.client.post(reverse('forgot_password'), {'email': self.email})

        # make sure the account is active
        self.account.status = AccountStatus.ACTIVE
        self.account.save()

        # confirm account
        data = {'password': 'password', 'passwordconfirm': 'password'}
        r = self.client.post(self._token_url(), data)
        self.assertRedirects(r, reverse('account-index'))

        account = Account.objects.get(pk=self.account.pk)
        # check password changed
        self.assertTrue(
            validate_launchpad_password('password',
                                        account.encrypted_password))

    def test_reset_password_when_account_active_no_password(self):
        r = self.client.post(reverse('forgot_password'), {'email': self.email})

        self.account.accountpassword.delete()
        # make sure the account is active
        self.account.status = AccountStatus.ACTIVE
        self.account.save()

        # confirm account
        data = {'password': 'Password1', 'passwordconfirm': 'Password1'}
        r = self.client.post(self._token_url(), data)
        self.assertRedirects(r, reverse('account-index'))

    def test_reset_password_when_account_deactivated(self):
        """Prevent password reset for unverified emails."""
        r = self.client.post(reverse('forgot_password'), {'email': self.email})

        # make sure the account is deactivated
        self.account.status = AccountStatus.DEACTIVATED
        self.account.save()

        # confirm account
        data = {'password': 'Password1', 'passwordconfirm': 'Password1'}
        r = self.client.post(self._token_url(), data)
        self.assertRedirects(r, reverse('account-index'))

    def test_reset_password_when_account_deactivated_no_preferred_email(self):
        # make sure the account is deactivated and preferred email is removed
        self.account.status = AccountStatus.DEACTIVATED
        # Blow out the cached value
        self.account.save()
        self.account.emailaddress_set.update(status=EmailStatus.NEW)

        self.account = Account.objects.get_by_email(self.email)

        if gargoyle.is_active('ALLOW_UNVERIFIED'):
            self.assertEqual(self.account.preferredemail.email, self.email)
        else:
            self.assertEqual(self.account.preferredemail, None)

        self.client.post(reverse('forgot_password'), {'email': self.email})

        # we sent an email anyway, despite there not being a validated email
        self.assertEqual(self.mock_send_email.call_count, 1)

    def test_reset_password_when_account_no_verified_emails(self):
        self.account.emailaddress_set.update(status=EmailStatus.NEW)
        self.client.post(reverse('forgot_password'), {'email': self.email})
        # we sent an email anyway, despite there not being a validated email
        self.assertEqual(self.mock_send_email.call_count, 1)

    def test_reset_password_unverified_email_but_account_verified_email(self):
        verified = self.account.verified_emails()
        unverified = self.factory.make_email_for_account(
            self.account, status=EmailStatus.NEW)
        self.client.post(reverse('forgot_password'),
                         {'email': unverified.email})
        # email sent to verified email addresses instead
        self.assertEqual(self.mock_send_email.call_count, len(verified))

    def test_reset_password_when_account_noaccount(self):
        r = self.client.post(reverse('forgot_password'), {'email': self.email})

        # make sure the account is deactivated
        self.account.status = AccountStatus.NOACCOUNT
        self.account.save()

        # confirm account
        data = {'password': 'Password1', 'passwordconfirm': 'Password1'}
        r = self.client.post(self._token_url(), data)
        self.assertRedirects(r, reverse('account-index'))

    def test_reset_password_when_account_suspended(self):
        r = self.client.post(reverse('forgot_password'), {'email': self.email})

        self.account.suspend()

        data = {'password': 'Password1', 'passwordconfirm': 'Password1'}

        # confirm account
        r = self.client.post(self._token_url(), data)
        self.assertRedirects(r, reverse('bad_token'))

    def test_reset_password_invalid_form(self):
        # get valid session
        r = self.client.post(reverse('forgot_password'), {'email': self.email})

        # test view
        r = self.client.post(self._token_url())
        self.assertTemplateUsed(r, 'registration/reset_password.html')
        self.assertFormError(r, 'form', 'password', 'Required field.')

    def test_reset_password_get(self):
        # get valid session
        r = self.client.post(reverse('forgot_password'), {'email': self.email})

        # test view
        r = self.client.get(self._token_url())
        self.assertTemplateUsed(r, 'registration/reset_password.html')
        for context in r.context:
            self.assertEqual(context['form'].errors, {})

    def test_bad_method(self):
        r = self.client.put(reverse('forgot_password'), {'email': self.email})
        self.assertEqual(r.status_code, 405)

    def test_reset_password_invalidate_tokens(self):
        # make sure the account is active
        assert self.account.status == AccountStatus.ACTIVE

        token = self.account.create_oauth_token('new-token')
        r = self.client.post(reverse('forgot_password'), {'email': self.email})

        # confirm account
        data = {'password': 'Password1', 'passwordconfirm': 'Password1'}
        r = self.client.post(self._token_url(), data)
        self.assertRedirects(r, reverse('account-index'))
        self.assertNotIn(token, self.account.oauth_tokens())


class LoggedInForgotPasswordTestCase(ForgotPasswordTestCase):
    # forgot_password and reset_password views should also work
    # for logged in users, repeat tests with an authenticated user

    def setUp(self):
        super(LoggedInForgotPasswordTestCase, self).setUp()
        self.authenticate()


class NewAccountSelectiveTestCase(UIViewsBaseTestCase):
    def test_new_account_selective_on_post_request(self):
        email = 'isdtest@canonical.com'
        condition_set = 'identityprovider.gargoyle.RequestDataConditionSet'
        self.conditionally_enable_flag('ALLOW_UNVERIFIED', 'email', email,
                                       condition_set)

        name = 'webui.views.ui.registration.new_account'
        with patch(name) as mock_new_account:
            mock_new_account.return_value = HttpResponse()
            self.client.post(reverse('new_account'), {'email': email})
        self.assertTrue(mock_new_account.called)

    def test_new_account_selective_on_get_request(self):
        email = 'isdtest@canonical.com'
        condition_set = 'identityprovider.gargoyle.RequestDataConditionSet'
        self.conditionally_enable_flag('ALLOW_UNVERIFIED', 'email', email,
                                       condition_set)

        name = 'webui.views.ui.registration.new_account'
        with patch(name) as mock_new_account:
            mock_new_account.return_value = HttpResponse()
            self.client.get(reverse('new_account'), {'email': email})
        self.assertTrue(mock_new_account.called)


class NewAccountTestCase(UIViewsBaseTestCase):

    def setUp(self):
        super(NewAccountTestCase, self).setUp()
        # force the use of the the old view
        switch = switches(ALLOW_UNVERIFIED=False)
        switch.patch()
        self.addCleanup(switch.unpatch)

    def test_new_account_when_form_validation_fails(self):
        r = self.client.post(reverse('new_account'), {'email': 'test'})
        self.assertTemplateUsed(r, 'registration/new_account.html')

    def test_new_account_when_captcha_fails(self):
        r = self.request_when_captcha_fails(
            reverse('new_account'), self.data)
        self.assertTemplateUsed(r, 'registration/new_account.html')

    def test_new_account_when_inactive(self):
        self.account.status = AccountStatus.NOACCOUNT
        self.account.save()
        r = self.post_new_account(email=self.email)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.mock_send_email.call_count, 0)

    def test_new_account_when_account_not_exists_no_token(self):
        self.post_new_account()
        token_obj = AuthToken.objects.get(
            email=self.new_email, token_type=TokenType.NEWPERSONLESSACCOUNT)
        self.assertEqual(token_obj.redirection_url, reverse('account-index'))

    def test_new_account_includes_rp_analytics(self):
        rpconfig = OpenIDRPConfig.objects.create(
            trust_root='http://example.com/',
            ga_snippet='[["_setAccount", "12345"]]')
        token = self._assign_token_to_rpconfig(rpconfig)
        response = self.client.get(
            reverse('new_account', kwargs=dict(token=token)))
        self.assertContains(response, "_gaq.push(['_setAccount', '12345']);")

    def test_do_not_loose_url_token_on_get(self):
        token = create_token(16)
        url = reverse('new_account', kwargs=dict(token=token))
        response = self.client.get(url)

        self.assertTemplateUsed(response, 'registration/new_account.html')

        tree = PyQuery(response.content)
        forms = tree.find('form')
        self.assertEqual(len(forms), 1)
        self.assertEqual(forms[0].get('action'), url)

    def test_do_not_loose_url_token_on_post_when_form_not_valid(self):
        token = create_token(16)
        # email already taken
        response = self.post_new_account(email='', token=token)

        self.assertTemplateUsed(response, 'registration/new_account.html')
        self.assertContains(response, 'Required field.')

        tree = PyQuery(response.content)
        action = reverse('new_account', kwargs=dict(token=token))
        forms = tree.find('form[action="%s"]' % action)
        self.assertEqual(len(forms), 1)

    def test_edit_account_template(self):
        self.data['next'] = reverse('account-edit')
        r = self.client.post(reverse('login'), self.data)
        r = self.client.get(reverse('account-edit'))
        self.assertTemplateUsed(r, 'account/edit.html')

        content = r.content
        newpassword_pattern = '<input (.*)name="password"(.*)>'
        newpasswdconfirm_pattern = '<input (.*)name="passwordconfirm"(.*)>'
        password_pattern = re.compile('.*type="password".*')
        autocomplete_ptn = re.compile('.*class=".*disableAutoComplete.*".*')
        newpassword = re.search(newpassword_pattern, content)
        newpasswordconfirm = re.search(newpasswdconfirm_pattern, content)

        def is_password_type(container):
            data = container.group(0) + container.group(1)
            result = re.search(password_pattern, data) is not None
            return result

        def is_autocomplete(container):
            data = container.group(0) + container.group(1)
            result = re.search(autocomplete_ptn, data) is not None
            return result

        self.assertTrue(is_password_type(newpassword))
        self.assertTrue(is_password_type(newpasswordconfirm))
        self.assertTrue(is_autocomplete(newpassword))
        self.assertTrue(is_autocomplete(newpasswordconfirm))


class ConfirmEmailTestCase(UIViewsBaseTestCase):

    def _setup_account_with_new_email(self):
        # create new email account
        email = self.factory.make_email_for_account(
            self.account, email=self.new_email, status=EmailStatus.NEW)
        # create verification token
        token = self.factory.make_authtoken(
            token_type=TokenType.VALIDATEEMAIL, email=email.email)
        return email, token

    def test_confirm_email_not_existing(self):
        self.authenticate()
        email, token = self._setup_account_with_new_email()
        # delete email account
        email.delete()
        # use verification token
        r = self.client.get(token.absolute_url)
        self.assertEqual(r.status_code, 404)

    def test_confirm_email_get(self):
        self.authenticate()

        email, token = self._setup_account_with_new_email()
        # use verification token
        self.client.get(token.absolute_url)

        # verify token has not been consumed, and email has not been
        # verified yet
        token = AuthToken.objects.get(
            token=token.token, token_type=TokenType.VALIDATEEMAIL)
        self.assertEqual(token.date_consumed, None)
        email = EmailAddress.objects.get(email=email.email)
        self.assertEqual(email.status, EmailStatus.NEW)

    def test_confirm_email_as_another_user_fails(self):
        self.authenticate()
        account = self.factory.make_account()

        r, token = self.get_email_token_validation_response(account)

        token_id = token.pk

        self.assertEqual(r.status_code, 404)
        self.assertEqual(0, AuthToken.objects.filter(pk=token_id).count())
        email = EmailAddress.objects.get(email=self.new_email)
        self.assertEqual(EmailStatus.NEW, email.status)

    def test_config_email_when_not_logged_in_redirects_to_login(self):
        r, token = self.get_email_token_validation_response(self.account)

        kwargs = dict(authtoken=token, email_address=self.new_email)
        url = (reverse('login') + '?next=' +
               urllib2.quote(reverse('confirm_email', kwargs=kwargs)))
        self.assertRedirects(r, url)

    def get_email_token_validation_response(self, account):
        email = self.factory.make_email_for_account(
            account, email=self.new_email, status=EmailStatus.NEW)
        token = self.factory.make_authtoken(
            token_type=TokenType.VALIDATEEMAIL, email=email.email)
        r = self.client.get(token.absolute_url)
        return r, token

    def test_suspended(self):
        r = self.client.get(reverse('suspended'))
        self.assertTemplateUsed(r, 'account/suspended.html')

    def test_invalid_email_does_not_blow_up(self):
        r = self.post_new_account(email='what<~@ever.com')
        self.assertEqual(200, r.status_code)
        self.assertContains(r, 'Invalid email')

    @switches(ALLOW_UNVERIFIED=False)
    def test_valid_email_redirects(self):
        r = self.post_new_account(email='what@ever.com')
        self.assertEqual(r.status_code, 200)


class CaptchaVerificationTestCase(BaseTestCase):
    success_status = 302

    def setUp(self):
        super(CaptchaVerificationTestCase, self).setUp()
        mock_handler = MockHandler()
        mock_handler.set_next_response('false\nno-challenge')
        Captcha.opener = urllib2.build_opener(mock_handler)
        self.addCleanup(setattr, Captcha, 'opener', None)

        old_disable = settings.DISABLE_CAPTCHA_VERIFICATION
        settings.DISABLE_CAPTCHA_VERIFICATION = False
        self.addCleanup(setattr, settings, 'DISABLE_CAPTCHA_VERIFICATION',
                        old_disable)

    def test_new_account_when_form_validation_fails(self):
        r = self.post_new_account()
        self.assertTemplateUsed(r, 'registration/new_account.html')
        msg = 'It appears that our captcha service was unable to load'
        self.assertContains(r, msg)

    def test_new_account_captcha_whitelist(self):
        email = 'canonicaltest@gmail.com'
        pattern = '^canonicaltest(?:\+.+)?@gmail\.com$'
        overrides = dict(
            DISABLE_CAPTCHA_VERIFICATION=False,
            EMAIL_WHITELIST_REGEXP_LIST=[pattern],
        )
        with patch_settings(**overrides):
            response = self.post_new_account(email=email)
            self.assertEqual(response.status_code, self.success_status)

    def test_new_account_captcha_whitelist_with_uuid(self):
        email = 'canonicaltest+something@gmail.com'
        pattern = '^canonicaltest(?:\+.+)?@gmail\.com$'
        overrides = dict(
            DISABLE_CAPTCHA_VERIFICATION=False,
            EMAIL_WHITELIST_REGEXP_LIST=[pattern],
        )
        with patch_settings(**overrides):
            response = self.post_new_account(email=email)
            self.assertEqual(response.status_code, self.success_status)

    @switches(CAPTCHA=True)
    def test_new_account_captcha_whitelist_fail(self):
        email = 'notcanonicaltest@gmail.com'
        pattern = '^canonicaltest(?:\+.+)?@gmail\.com$'
        overrides = dict(
            DISABLE_CAPTCHA_VERIFICATION=False,
            EMAIL_WHITELIST_REGEXP_LIST=[pattern],
        )
        with patch_settings(**overrides):
            response = self.post_new_account(email=email)
            msg = 'It appears that our captcha service was unable to load'
            self.assertContains(response, msg)


class CaptchaVerificationTestCaseOldFlow(CaptchaVerificationTestCase):
    success_status = 200

    def setUp(self):
        super(CaptchaVerificationTestCaseOldFlow, self).setUp()
        patch = switches(ALLOW_UNVERIFIED=False)
        patch.patch()
        self.addCleanup(patch.unpatch)


@skipUnless(settings.BRAND == 'ubuntu',
            "Language pngs are only used for the ubuntu brand.""")
class LanguagesTestCase(BaseTestCase):

    def test_preffered_lang_is_preserved_after_logout(self):
        self.account.preferredlanguage = 'es'
        self.account.save()

        self.authenticate()
        r = self.client.get(reverse('account-index'))
        self.assertContains(r, 'es.png')

        self.client.get(reverse('logout'))
        r = self.client.get(reverse('account-index'))
        self.assertContains(r, 'es.png')

    def test_language_selected_before_login_is_preserved(self):
        self.assertNotContains(self.client.get(reverse('account-index')),
                               'es.png')
        self.client.post(reverse('set_language'), {'language': 'es'})
        self.assertContains(self.client.get(reverse('account-index')),
                            'es.png')
        self.authenticate()
        self.assertContains(self.client.get(reverse('account-index')),
                            'es.png')


class CookiesTestCase(SSOBaseTestCase):

    def setUp(self):
        super(CookiesTestCase, self).setUp()
        _disable_cookie_check = decorators.disable_cookie_check
        decorators.disable_cookie_check = False
        Session.objects.all().delete()
        self.addCleanup(setattr, decorators, 'disable_cookie_check',
                        _disable_cookie_check)

    def _get(self, url, *params):
        r = self.client.get(url)
        # The following line makes this cookieless:
        self.client.cookies.clear()
        if 300 <= r.status_code < 400:
            location = r['Location']
            scheme, netloc, path, query, fragment = urlsplit(location)
            return self._get(path, QueryDict(query))
        else:
            return r

    def _check_url(self, url):
        r = self._get(url)
        self.assertContains(r, '<title>Cookies required</title>')

        r = self.client.get(url, follow=True)
        self.assertNotContains(r, '<title>Cookies required</title>')

    def _count_sessions(self):
        return Session.objects.all().count()

    def test_login(self):
        self._check_url(reverse('login'))

    def test_account_index(self):
        url = reverse('account-index')

        r = self.client.get(url)

        self.assertEqual(r.status_code, 200)
        self.assertNotContains(r, '<title>Cookies required</title>')

    def test_forgot_password(self):
        self._check_url(reverse('forgot_password'))

    def test_new_account(self):
        self._check_url(reverse('new_account'))

    def test_cookie_is_sessionless(self):
        self.client.get(reverse('login'))
        self.assertEqual(self._count_sessions(), 0)


class LoginFlowStatsTestCase(BaseTestCase):

    args_list = partial(_args_list, flow_name='flows.login')

    def test_login_stats(self):
        self.client.get(reverse('login'))
        self.client.post(reverse('login'), self.data)
        self.assertEqual(self.mock_increment.call_args_list, self.args_list())

    def test_login_error_stats(self):
        self.client.get(reverse('login'))
        # make sure to pass invalid data
        self.client.post(reverse('login'), {'account': 'invalid'})
        self.assertEqual(self.mock_increment.call_args_list,
                         self.args_list(key='error'))


class NewAccountFlowStatsTestCase(BaseTestCase):

    args_list = partial(_args_list, flow_name='flows.new_account')

    def setUp(self):
        super(NewAccountFlowStatsTestCase, self).setUp()
        # force the use of the the old view
        switch = switches(ALLOW_UNVERIFIED=False)
        switch.patch()
        self.addCleanup(switch.unpatch)

    def test_new_account(self):
        self.client.get(reverse('new_account'))
        self.post_new_account(email='test@test.com', follow=True)

        # confirm account
        token = AuthToken.objects.get(
            email='test@test.com', token_type=TokenType.NEWPERSONLESSACCOUNT)
        self.client.post(token.absolute_url, {'post': 'yes'})
        self.assertEqual(self.mock_increment.call_args_list, self.args_list())

    @patch('webui.views.ui.verify_token_string')
    def test_confirm_account_bad_token(self, mock_verify_token_string):
        mock_verify_token_string.return_value = None

        self.client.get(reverse('new_account'))
        self.post_new_account(email='test@test.com', follow=True)

        # confirm account
        token = AuthToken.objects.get(
            email='test@test.com', token_type=TokenType.NEWPERSONLESSACCOUNT)
        self.client.post(token.absolute_url, {'post': 'yes'})

        self.assertEqual(self.mock_increment.call_args_list,
                         self.args_list(key='error.token'))

    def test_new_account_form_error(self):
        self.client.get(reverse('new_account'))
        self.client.post(reverse('new_account'), {'foo': 'invalid'})
        self.assertEqual(self.mock_increment.call_args_list,
                         self.args_list(key='error.form'))

    def test_new_account_email_error(self):
        self.client.get(reverse('new_account'))
        response = self.post_new_account(email='foo.bar')
        self.assertFormError(response, 'form', 'email', 'Invalid email.')

    @patch('webui.views.ui._verify_captcha_response')
    def test_new_account_captcha_error(
            self, mock_verify_captcha_response):
        mock_verify_captcha_response.return_value = HttpResponse()
        self.client.get(reverse('new_account'))
        self.post_new_account()
        self.assertEqual(self.mock_increment.call_args_list,
                         self.args_list(key='error.captcha'))


class ForgotPasswordFlowStatsTestCase(UIViewsBaseTestCase):

    args_list = partial(_args_list, flow_name='flows.forgot_password')

    def forgot_password(self, data=None):
        self.client.get(reverse('forgot_password'))
        if data is None:
            data = {'email': self.email}
        self.client.post(reverse('forgot_password'), data)

    def reset_password(self, valid_password=True):
        data = {'password': 'Password1', 'passwordconfirm': 'Password1'}
        if not valid_password:
            data['passwordconfirm'] = 'invalid'
        self.client.post(self._token_url(), data)

    def test_forgot_password(self):
        self.forgot_password()
        self.reset_password()
        self.assertEqual(self.mock_increment.call_args_list, self.args_list())

    def test_forgot_password_form_error(self):
        self.forgot_password(data={'foo': 'invalid'})
        self.assertEqual(self.mock_increment.call_args_list,
                         self.args_list(key='error.form'))

    @patch('webui.views.ui.verify_token_string')
    def test_reset_password_token_error(self, mock_verify_token_string):
        mock_verify_token_string.return_value = None
        self.forgot_password()
        self.reset_password()
        self.assertEqual(self.mock_increment.call_args_list,
                         self.args_list(key='error.token'))

    def test_reset_password_form_error(self):
        self.forgot_password()
        self.reset_password(valid_password=False)
        self.assertEqual(self.mock_increment.call_args_list,
                         self.args_list(key='error.form'))


class TwoFactorLoginTestCase(SSOBaseTestCase):
    email = 'user2f@example.com'
    password = DEFAULT_USER_PASSWORD
    logout_link = 'a[href="/+logout"]'

    def setUp(self):
        super(TwoFactorLoginTestCase, self).setUp()
        self.account = self.factory.make_account('2f User', self.email,
                                                 self.password)
        self.switch = switches(TWOFACTOR=True)
        self.switch.__enter__()
        self.addCleanup(self.switch.__exit__, None, None, None)

    def do_login(self, **kwargs):
        data = {'email': self.email, 'password': self.password}
        token = kwargs.pop('token', None)
        data.update(kwargs)
        if token:
            url = reverse('login', kwargs={'token': token})
        else:
            url = reverse('login')
        return self.client.post(url, data)

    def do_twofactor(self, oath_token, next=None):
        data = {'oath_token': oath_token}
        if next:
            data['next'] = next
        return self.client.post(reverse('twofactor'), data)

    def test_twofactor_login_disabled_when_readonly(self):
        rm = ReadOnlyManager()
        rm.set_readonly()
        self.addCleanup(rm.clear_readonly)

        with switches(TWOFACTOR=True):
            self.do_login()
            response = self.client.get(reverse('twofactor'))
        self.assertEqual(response.status_code, 404)

    @patch('webui.views.ui.twofactor.site_requires_twofactor_auth')
    def test_when_site_does_not_require_twofactor_no_oath_field(
            self, mock_site):
        mock_site.return_value = False
        response = self.client.get(reverse('login'))
        tree = PyQuery(response.content)
        self.assertEqual(len(tree.find('input[name="oath_token"]')), 0)

    @patch('webui.views.ui.twofactor.site_requires_twofactor_auth')
    def test_when_site_requires_twofactor_oath_field_is_present(
            self, mock_site):
        mock_site.return_value = True
        response = self.client.get(reverse('login'))
        tree = PyQuery(response.content)
        inputs = tree.find('input[name="oath_token"]')
        self.assertEqual(len(inputs), 1)
        oath = inputs[0]
        self.assertEqual(oath.attrib['autocomplete'], 'off')

    @patch('webui.views.ui.twofactor.site_requires_twofactor_auth')
    def test_when_site_requires_twofactor_oath_field_is_present_lp(
            self, mock_site):
        mock_site.return_value = True
        response = self.client.get(reverse('login'))
        tree = PyQuery(response.content)
        inputs = tree.find('input[name="oath_token"]')
        self.assertEqual(len(inputs), 1)
        oath = inputs[0]
        self.assertEqual(oath.attrib['autocomplete'], 'off')

    @patch('webui.views.ui.twofactor.user_requires_twofactor_auth')
    def test_when_user_requires_twofactor_redirected(self, mock_user):
        mock_user.return_value = True
        r = self.do_login()
        self.assertRedirects(r, reverse('twofactor'))

    @patch('webui.views.ui.twofactor.user_requires_twofactor_auth')
    def test_when_user_requires_twofactor_redirected_with_token(
            self, mock_user):
        mock_user.return_value = True
        token = 'a' * 16
        r = self.do_login(token=token)
        self.assertRedirects(r, reverse('twofactor', kwargs=dict(token=token)))

    @patch('webui.views.ui.twofactor.user_requires_twofactor_auth')
    def test_when_user_requires_twofactor_redirected_with_next(
            self, mock_user):
        mock_user.return_value = True
        r = self.do_login(next=reverse('account-edit'))
        self.assertRedirects(r, '/two_factor_auth?next=/%2Bedit')

    @patch('webui.views.ui.twofactor.site_requires_twofactor_auth')
    @patch('webui.views.ui.authenticate_device')
    def test_full_twofactor_login_redirected_to_next(
            self, mock_auth, mock_site):
        mock_auth.return_value = True
        mock_site.return_value = True
        r = self.do_login(next=reverse('account-edit'), oath_token='123456')
        mock_auth.assert_called_once_with(self.account, '123456')
        self.assertRedirects(r, reverse('account-edit'))

    @patch('webui.views.ui.twofactor.site_requires_twofactor_auth')
    def test_full_twofactor_login_illformed_token_displays_error(
            self, mock_site):
        mock_site.return_value = True
        response = self.do_login(next=reverse('account-edit'),
                                 oath_token='XXX')
        tree = PyQuery(response.content)
        self.assertEqual(len(tree.find('input[name="oath_token"]')), 1)
        error = tree.find('#oathtoken span.error')
        self.assertEqual(len(error), 1)
        self.assertEqual(error[0].text.strip(), ONE_TIME_PWD_ERROR)

    @patch('webui.views.ui.twofactor.site_requires_twofactor_auth')
    @patch('webui.views.ui.authenticate_device')
    def test_full_twofactor_login_invalid_code_displays_error(
            self, mock_auth, mock_site):
        mock_auth.side_effect = ui.AuthenticationError("ERRORMSG")
        mock_site.return_value = True
        response = self.do_login(next=reverse('account-edit'),
                                 oath_token='123456')
        tree = PyQuery(response.content)
        self.assertEqual(len(tree.find('input[name="oath_token"]')), 1)
        error = tree.find('#oathtoken span.error')
        self.assertEqual(len(error), 1)
        self.assertEqual(error[0].text.strip(), "ERRORMSG")
        mock_auth.assert_called_once_with(self.account, '123456')

    @patch('webui.views.ui.twofactor.site_requires_twofactor_auth')
    @patch('webui.views.ui.authenticate_device')
    def test_full_twofactor_login_invalid_code_displays_unicode_error(
            self, mock_auth, mock_site):
        mock_auth.side_effect = ui.AuthenticationError(u"客")
        mock_site.return_value = True
        response = self.do_login(next=reverse('account-edit'),
                                 oath_token='123456')
        tree = PyQuery(response.content.decode('utf8'))
        self.assertEqual(len(tree.find('input[name="oath_token"]')), 1)
        error = tree.find('#oathtoken span.error')
        self.assertEqual(len(error), 1)
        self.assertTrue(error[0].text == u"客")

    @patch('webui.views.ui.authenticate_device')
    def test_twofactor_step_redirected_to_next(self, mock_auth):
        mock_auth.return_value = True
        self.client.login(username=self.email, password=self.password)
        r = self.do_twofactor(next=reverse('account-edit'),
                              oath_token='123456')
        self.assertRedirects(r, reverse('account-edit'))
        mock_auth.assert_called_once_with(self.account, '123456')

    def test_twofactor_step_illformed_token_displays_error(self):
        self.client.login(username=self.email, password=self.password)
        response = self.do_twofactor(next=reverse('account-edit'),
                                     oath_token='XXX')
        tree = PyQuery(response.content)
        self.assertEqual(len(tree.find('input[name="oath_token"]')), 1)
        error = tree.find('#oathtoken span.error')
        self.assertEqual(len(error), 1)
        self.assertEqual(error[0].text.strip(), ONE_TIME_PWD_ERROR)

    @patch('webui.views.ui.authenticate_device')
    def test_twofactor_step_invalid_code_displays_error(self, mock_auth):
        mock_auth.side_effect = ui.AuthenticationError("ERRORMSG")
        self.client.login(username=self.email, password=self.password)
        response = self.do_twofactor(next=reverse('account-edit'),
                                     oath_token='123456')
        tree = PyQuery(response.content)
        self.assertEqual(len(tree.find('input[name="oath_token"]')), 1)
        error = tree.find('#oathtoken span.error')
        self.assertEqual(len(error), 1)
        self.assertEqual(error[0].text.strip(), "ERRORMSG")
        mock_auth.assert_called_once_with(self.account, '123456')

    @patch('webui.views.ui.twofactor.user_requires_twofactor_auth')
    def test_two_factor_includes_rp_analytics(self, mock_user_requires_2f):
        mock_user_requires_2f.return_value = True
        rpconfig = OpenIDRPConfig.objects.create(
            trust_root='http://example.com/',
            ga_snippet='[["_setAccount", "12345"]]')
        token = 'averyrandomtoken'
        response = self.do_login(token=token)
        self._assign_token_to_rpconfig(rpconfig, token=token)
        url = reverse('twofactor', kwargs=dict(token=token))
        self.assertRedirects(response, url)

        response = self.client.get(url)

        self.assertContains(response, "_gaq.push(['_setAccount', '12345']);")

    @skipUnless(settings.BRAND == 'ubuntu',
                "A sidebar appears only in ubuntu brand.""")
    @patch('webui.views.ui.twofactor.user_requires_twofactor_auth')
    def test_two_factor_only_hides_sidebar_from_2f_page(self,
                                                        mock_user_requires_2f):
        mock_user_requires_2f.return_value = True
        rpconfig = OpenIDRPConfig.objects.create(
            trust_root='http://example.com/',
            ga_snippet='[["_setAccount", "12345"]]')
        token = 'averyrandomtoken'

        # First, test the sidebar is visible on the regular login page
        url = reverse('login', kwargs={'token': token})
        response = self.client.get(url)
        tree = PyQuery(response.content)
        self.assertEqual(len(tree.find('#sidebar')), 1)

        # Then confirm it's not displayed in the 2 factor page
        response = self.do_login(token=token)
        self._assign_token_to_rpconfig(rpconfig, token=token)
        response = self.client.get(
            reverse('twofactor', kwargs=dict(token=token)))
        tree = PyQuery(response.content)
        self.assertEqual(len(tree.find('#sidebar')), 0)

    def test_twofactor_provides_logout(self):
        self.client.login(username=self.email, password=self.password)
        response = self.client.get(reverse('twofactor'))

        tree = PyQuery(response.content)
        logout_link = tree.find(self.logout_link)
        self.assertTrue(len(logout_link) > 0)

    def test_show_user_details(self):
        self.client.login(username=self.email, password=self.password)
        response = self.client.get(reverse('twofactor'))

        self.assertContains(response, self.account.displayname)


class TwoFactorLoginLPTestCase(TwoFactorLoginTestCase):
    """This testcase inherits its tests from TwoFactorLoginTestCase in order to
    run exactly the same tests against the LP templates"""

    logout_link = 'form[action="/+logout"]'

    def setUp(self):
        super(TwoFactorLoginLPTestCase, self).setUp()
        brand_patch = patch_settings(BRAND='launchpad')
        brand_patch.start()
        self.addCleanup(brand_patch.stop)

    def test_lp_templates_render_correctly(self):
        """Test that the lp twofactor template renders properly"""
        self.do_login()
        response = self.client.get(reverse('twofactor'))
        self.assertNotIn('Email address', response.content)
        self.assertNotIn('Password', response.content)


class TwoFactorFunctionsTestCase(SSOBaseTestCase):

    def test_user_requires_twofactor_auth(self):
        def f(require2f, has_devices, returns, logs):
            with patch('logging.warning') as mock_warning:
                with patch('webui.views.ui.twofactor.'
                           'is_twofactor_enabled') as mock_flag:
                    mock_flag.return_value = True
                    account = Mock()
                    account.twofactor_required = require2f
                    account.has_twofactor_devices.return_value = has_devices
                    r = twofactor.user_requires_twofactor_auth(None, account)
                    self.assertEqual(returns, r)
                    self.assertEqual(logs, mock_warning.called)
        f(require2f=False, has_devices=False, returns=False, logs=False)
        f(require2f=False, has_devices=True, returns=False, logs=False)
        f(require2f=True, has_devices=False, returns=False, logs=True)
        f(require2f=True, has_devices=True, returns=True, logs=False)

    def _make_mock_account(self, *args):
        def _make_device(ret):
            m = Mock()
            m.authenticate.return_value = ret
            return m
        devices = [_make_device(a) for a in args]
        account = Mock()
        account.devices.order_by.return_value = devices
        return account, devices

    def test_authenticate_with_no_valid_devices_throws(self):
        account, _ = self._make_mock_account(False, False)
        self.assertRaises(ui.AuthenticationError, ui.authenticate_device,
                          account, '123456')

    def test_authenticate_with_first_device_succeeds(self):
        account, devices = self._make_mock_account(True, False)
        self.assertTrue(ui.authenticate_device(account, '123456'))
        self.assertTrue(devices[0].authenticate.called)
        self.assertFalse(devices[1].authenticate.called)

    def test_authenticate_with_last_device_succeeds(self):
        account, devices = self._make_mock_account(False, True)
        self.assertTrue(ui.authenticate_device(account, '123456'))
        self.assertTrue(devices[0].authenticate.called)
        self.assertTrue(devices[1].authenticate.called)


class ComboViewTestCase(SSOBaseTestCase):

    def test_combine_files(self):
        response = self.client.get(
            settings.COMBO_URL +
            '?yui/3.3.0/widget/widget-base.js'
            '&identityprovider/ubuntuone/js/ie/html5shiv.js')

        self.assertEqual(response['content-type'], 'text/javascript')
        self.assertNotContains(response, '[missing]')
        self.assertContains(response, '/* yui/3.3.0/widget/widget-base.js */')
        self.assertContains(
            response,
            '/* identityprovider/ubuntuone/js/ie/html5shiv.js */')
