# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

import urllib

from datetime import datetime
from urlparse import urljoin, urlparse

import mock

from django.core import mail
from django.core.urlresolvers import NoReverseMatch, reverse
from django.conf import settings
from django.contrib.auth.models import User
from gargoyle.testutils import switches
from oauth_backend.models import Consumer, Token
from pyquery import PyQuery
from unittest import skipUnless

from identityprovider.const import SESSION_TOKEN_KEY, SESSION_TOKEN_NAME
from identityprovider.models import (
    Account,
    AuthToken,
    EmailAddress,
    InvalidatedEmailAddress,
    OpenIDRPConfig,
)
from identityprovider.models.const import (
    AccountStatus,
    EmailStatus,
    TokenType,
)
from identityprovider.tests import DEFAULT_USER_PASSWORD
from identityprovider.tests.utils import (
    MISSING_BACKUP_DEVICE,
    AuthenticatedTestCase,
    SSOBaseTestCase,
    assert_exausted_warning,
    patch_settings,
)
from identityprovider.utils import validate_launchpad_password
from webui import decorators


class AccountEmailsViewTestCase(AuthenticatedTestCase):

    def setUp(self):
        super(AccountEmailsViewTestCase, self).setUp()
        self.phone_email = EmailAddress.objects.create_from_phone_id(
            'tel:+1234567890', self.account)

    def test_phone_id_email_is_not_verifiable(self):
        url = reverse('account-emails')
        response = self.client.get(url)
        tree = PyQuery(response.content)
        # unverified emails -> second listing table
        unverified_emails = tree.find('table.listing')[1]
        emails_td = PyQuery(unverified_emails).find('td.email')
        for email_td in emails_td:
            if email_td.text == self.phone_email.email:
                # get available actions
                actions = email_td.getnext().getchildren()
                # only delete option available, is not verifiable
                self.assertEqual(len(actions), 1)
                self.assertEqual(actions[0].get('href'),
                                 '.%s?id=%d' % (reverse('delete_email'),
                                                self.phone_email.id))
            else:
                # get available actions: verify, remove
                actions = email_td.getnext().getchildren()
                self.assertEqual(len(actions), 2)


class AccountViewsUnauthenticatedTestCase(SSOBaseTestCase):

    def ensure_cookie_check_enabled(self):
        # Make sure the tests don't run with cookie checks disabled
        # otherwise checking that the redirect doesn't happen is
        # useless.
        patcher = mock.patch.object(decorators, 'disable_cookie_check', False)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_index_unauthenticated(self):
        self.ensure_cookie_check_enabled()

        r = self.client.get(reverse('account-index'))

        self.assertEqual(r.status_code, 200)

    def test_index_xrds(self):
        self.ensure_cookie_check_enabled()
        accept = "application/xrds+xml; q=1, text/html; q=0.9"

        response = self.client.get(reverse('account-index'),
                                   HTTP_ACCEPT=accept)

        self.assertEqual(response.status_code, 200)
        self.assertTrue('Accept' in response['Vary'].split(','))
        self.assertFalse('X-XRDS-Location' in response)
        self.assertTrue('application/xrds+xml' in response['Content-Type'])

    def test_index_html(self):
        self.ensure_cookie_check_enabled()

        response = self.client.get(reverse('account-index'))

        self.assertEqual(response.status_code, 200)
        self.assertTrue('Accept' in response['Vary'].split(','))
        self.assertTrue('X-XRDS-Location' in response)
        self.assertTrue('text/html' in response['Content-Type'])

    def test_account_edit_anonymous(self):
        url = reverse('account-edit')
        response = self.client.get(url)
        login_url = reverse('login') + '?next=' + urllib.quote(url)
        self.assertRedirects(response, login_url)

    def test_includes_create_account_form_for_u1_brand(self):
        with mock.patch.multiple(settings, BRAND='ubuntu'):
            with switches(BRAND_UBUNTUONE=True):
                r = self.client.get(reverse('account-index'))

        self.assertIn('create_account_form', r.context)


class AccountViewStandAloneTestCase(AuthenticatedTestCase):
    """Contains the tests that are agnostic to TWOFACTOR issues."""

    url = reverse('account-edit')

    def test_index_authenticated(self):
        r = self.client.get(self.url)
        self.assertTemplateUsed(r, 'account/edit.html')

    def test_index_edit_displayname(self):
        data = {'displayname': "New Display Name",
                'preferred_email': self.account.preferredemail.id}
        r = self.client.post(self.url, data)
        self.assertEqual(r.status_code, 302)

    def test_index_edit_password(self):
        oauth_tokens = self.account.oauth_tokens()
        # web login token should be there
        assert oauth_tokens
        orig_token = oauth_tokens[0]

        data = {
            'displayname': "New Display Name",
            'preferred_email': self.account.preferredemail.id,
            'password': 'new-Password',
            'passwordconfirm': 'new-Password',
            'accept_tos': True
        }
        r = self.client.post(self.url, data)
        account = Account.objects.get(displayname='New Display Name')
        self.assertEqual(r.status_code, 302)
        self.assertTrue(validate_launchpad_password(
            'new-Password', account.accountpassword.password))
        oauth_tokens = account.oauth_tokens()
        self.assertEqual(oauth_tokens.count(), 1)
        # previous token was invalidated
        self.assertNotIn(orig_token, oauth_tokens)
        # new session is set up
        session_token_key = self.client.session.get(SESSION_TOKEN_KEY)
        self.assertEqual(session_token_key, oauth_tokens[0].token)

    @switches(ALLOW_UNVERIFIED=True)
    def test_index_cannot_edit_preferred_if_unverified(self):
        for email in self.account.emailaddress_set.all():
            email.status = EmailStatus.NEW
            email.save()
        self.account.save()
        r = self.client.get(self.url)
        dom = PyQuery(r.content)
        inputs = dom.find(
            "input[value='%s']" % self.account.preferredemail.email)
        self.assertEqual(len(inputs), 1)
        self.assertEqual(inputs[0].attrib['disabled'], 'true')

    def test_index_clears_up_message_from_session(self):
        self.client.session['message'] = 'test message'
        self.client.get(self.url)

        self.assert_('message' not in self.client.session)

    def test_verify_email_already_verified(self):
        r = self.client.get(reverse('verify_email'), {'id': 1})
        self.assertEqual(r.status_code, 404)

    def test_verify_email_other_users_email(self):
        other_account = self.factory.make_account()
        other_email = self.factory.make_email_for_account(
            account=other_account, status=EmailStatus.NEW)
        r = self.client.get(reverse('verify_email'), {'id': other_email.id})
        self.assertEqual(r.status_code, 404)

    def test_verify_email_success(self):
        email = EmailAddress.objects.create(
            email='footest@bar.com',
            account=self.account,
            status=EmailStatus.NEW)
        r = self.client.get(reverse('verify_email'), {'id': email.id})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(mail.outbox), 1)

    def test_new_email_get(self):
        r = self.client.get(reverse('new_email'))
        self.assertTemplateUsed(r, 'account/new_email.html')

    def test_new_email_post(self):
        r = self.client.post(reverse('new_email'),
                             {'newemail': "very-new-email@example.com"})
        self.assertEqual(r.status_code, 200)

    def test_new_email_post_with_token(self):
        url = reverse('new_email', kwargs=dict(token='thisissuperrando'))
        self.client.post(url, {'newemail': "very-new-email@example.com"})
        self.assertEqual(len(mail.outbox), 1)

    def test_new_email_previously_invalidated(self):
        email = EmailAddress.objects.create(
            email='footest@bar.com',
            account=self.account,
            status=EmailStatus.NEW)
        email.invalidate()
        response = self.client.post(
            reverse('new_email'), {'newemail': "footest@bar.com"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue('form' in response.context)
        form = response.context['form']
        self.assertEqual(len(form.errors), 1)
        self.assertEqual(form.errors.get('newemail'),
                         ['Email previously invalidated for this account.'])

    def test_new_email_invalidated_for_different_user(self):
        another_account = self.factory.make_account()
        email = EmailAddress.objects.create(
            email='footest@bar.com',
            account=another_account,
            status=EmailStatus.NEW)
        email.invalidate()
        response = self.client.post(
            reverse('new_email'), {'newemail': "footest@bar.com"})
        self.assertEqual(response.status_code, 200)
        added = self.account.emailaddress_set.get(email='footest@bar.com')
        self.assertEqual(added.status, EmailStatus.NEW)
        self.assertEqual(len(mail.outbox), 1)

    def test_account_index_includes_rp_analytics(self):
        rpconfig = OpenIDRPConfig.objects.create(
            trust_root='http://localhost/',
            ga_snippet='[["_setAccount", "12345"]]')
        token = self._assign_token_to_rpconfig(rpconfig)

        url = reverse('account-edit', kwargs=dict(token=token))
        response = self.client.get(url)
        self.assertContains(response, "_gaq.push(['_setAccount', '12345']);")


class AccountEditTestCase(AuthenticatedTestCase):

    url = reverse('account-edit')

    # the following flags will be used in test inheritance to assert over
    # all the possible combinations
    twofactor_enabled = False
    user_wants_twofactor = False
    user_wants_warn = True
    devices_count = 0
    paper_device_exhausted = 0

    def setUp(self):
        super(AccountEditTestCase, self).setUp()
        if self.twofactor_enabled is not None:
            self.switch = switches(TWOFACTOR=self.twofactor_enabled)
            self.switch.patch()
            self.addCleanup(self.switch.unpatch)

        self.account.twofactor_required = self.user_wants_twofactor
        self.account.warn_about_backup_device = self.user_wants_warn
        self.account.save()

        for i in xrange(self.devices_count):
            self.factory.make_device(account=self.account)

        assert self.account.devices.count() == self.devices_count

        if self.devices_count > 0 and self.paper_device_exhausted:
            counter = (settings.TWOFACTOR_PAPER_CODES -
                       settings.TWOFACTOR_PAPER_CODES_WARN_RENEWAL + 1)
            device = self.account.devices.all()[0]
            device.counter = counter
            device.device_type = 'paper'
            device.save()

    def test_authentication_device_section(self):
        response = self.client.get(self.url)
        device_identifier = 'authentication_devices'
        if self.twofactor_enabled is False or self.devices_count == 0:
            # Since the user has no devices, do not show the Devices section
            self.assertNotContains(response, device_identifier)
        else:
            self.assertContains(response, device_identifier)

    def test_backup_device_warning(self):
        response = self.client.get(self.url)
        backup_warning = MISSING_BACKUP_DEVICE.format(
            add_device_link=reverse('device-addition'))

        if (self.twofactor_enabled is False or self.devices_count != 1 or
                not self.user_wants_warn):
            self.assertNotContains(response, backup_warning)
        else:
            self.assertContains(response, backup_warning)

    def test_codes_nearly_exhausted_warning(self):
        response = self.client.get(self.url)
        devices = self.account.devices.all()

        if (self.twofactor_enabled and self.devices_count > 0 and
                self.paper_device_exhausted):
            assert_exausted_warning(self, devices, response)
        else:
            with self.assertRaises(AssertionError):
                assert_exausted_warning(self, devices, response)

    def test_device_preferences_with_twofactor_disabled(self):
        name = 'webui.views.account.is_twofactor_enabled'
        with mock.patch(name) as mock_enabled:
            mock_enabled.return_value = False
            response = self.client.get(self.url)
        self.assertFalse(response.context['enable_device_prefs'])

    def test_device_preferences_not_lost(self):
        data = dict(
            displayname=self.account.displayname,
            preferred_email=self.account.preferredemail.id,
        )
        if self.twofactor_enabled in (True, None):
            data['twofactor_required'] = self.user_wants_twofactor
            data['warn_about_backup_device'] = self.user_wants_warn

        response = self.client.post(self.url, data, follow=True)
        self.assertContains(
            response, 'Your account details have been successfully updated')

        # reload account
        account = Account.objects.get(id=self.account.id)
        # boolean preferences for devices does not change
        self.assertEqual(account.twofactor_required, self.user_wants_twofactor)
        self.assertEqual(account.warn_about_backup_device,
                         self.user_wants_warn)

    @switches(ALLOW_UNVERIFIED=False)
    def test_preferredemail_none(self):
        self.account.emailaddress_set.update(status=EmailStatus.NEW)
        assert self.account.preferredemail is None

        response = self.client.get(self.url)
        email_input = PyQuery(response.content).find(
            'input[type="text"][disabled="true"]')
        self.assertEqual(len(email_input), 1)
        self.assertEqual(email_input[0].get('value'), '')


class WithExhaustedDevice(AccountEditTestCase):
    twofactor_enabled = True
    devices_count = 1
    paper_device_exhausted = True


class WithTwoFactorDisabledWithDeviceTestCase(AccountEditTestCase):

    # Same settings as parent but with one device. Since twofactor_enabled is
    # still disabled, no test changes (no device section nor warning should be
    # shown).
    twofactor_enabled = False
    user_wants_warn = True
    devices_count = 1


class WithTwoFactorDisabledWithDeviceNoWarningTestCase(
        WithTwoFactorDisabledWithDeviceTestCase):

    # Same scenario as parent but user (somehow) set to False the
    # warn_about_backup_device setting.
    twofactor_enabled = False
    user_wants_warn = False
    devices_count = 1


class WithTwoFactorEnabledTestCase(AccountEditTestCase):

    # Even though twofactor_enabled holds, since user has no devices,
    # no device section nor warning should be shown.
    twofactor_enabled = True
    user_wants_warn = True
    devices_count = 0


class WithTwoFactorEnabledWithDeviceTestCase(WithTwoFactorEnabledTestCase):

    # With these settings we start to assert over device stuff (since
    # twofactor_enabled is enabled, and the user has one device).
    twofactor_enabled = True
    user_wants_warn = True
    devices_count = 1

    def test_twofactor_required_post_with_change_to_always(self):
        data = dict(
            displayname=self.account.displayname,
            preferred_email=self.account.preferredemail.id,
            twofactor_required=True,
        )

        response = self.client.post(self.url, data=data)
        # do not use assertRedirects since the sentence:
        #
        # self.assertRedirects(response, self.url)
        #
        # fails with:
        #
        # AssertionError: 302 != 200 : Couldn't retrieve redirection page '/':
        # response code was 302 (expected 200)
        #
        # because going to /, with twofactor_required set to True, actually
        # redirects to /two_factor_auth?next=/
        self.assertEqual(response.status_code, 302)
        data = urlparse(response['Location'])
        self.assertEqual(data.path, self.url)

        account = Account.objects.get(id=self.account.id)  # reload
        self.assertTrue(account.twofactor_required)

    def test_twofactor_required_post_with_change_to_as_needed(self):
        data = dict(
            displayname=self.account.displayname,
            preferred_email=self.account.preferredemail.id,
            twofactor_required=False,
        )
        response = self.client.post(self.url, data=data)
        self.assertRedirects(response, self.url)

        account = Account.objects.get(id=self.account.id)  # reload
        self.assertFalse(account.twofactor_required)

    def test_device_elements(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)

        tree = PyQuery(response.content)
        radios = tree.find('input[type="radio"]')
        self.assertEqual(len(radios), 2)

        tree = PyQuery(response.content)
        checkboxes = tree.find('input[type="checkbox"]')
        self.assertEqual(len(checkboxes), 1)


class WithTwoFactorEnabledWithDeviceNoWarningTestCase(
        WithTwoFactorEnabledWithDeviceTestCase):

    # Same behaviour as parent, since even if the user disabled the
    # warn_about_backup_device, the device settings and form processing
    # should behave exactly the same as if the setting was True.
    twofactor_enabled = True
    user_wants_warn = False
    devices_count = 1


class WithTwoFactorEnabledWithDevicesTestCase(
        WithTwoFactorEnabledWithDeviceTestCase):

    # Same as parent but with 2 devices.
    twofactor_enabled = True
    user_wants_warn = True
    devices_count = 2


class WithTwoFactorEnabledWithDevicesNoWarningTestCase(
        WithTwoFactorEnabledWithDevicesTestCase):

    # Same as parent with 2 devices and user disabling the setting
    # warn_about_backup_device.
    twofactor_enabled = True
    user_wants_warn = False
    devices_count = 2


class AccountTemplateTestCase(
        WithTwoFactorEnabledWithDeviceTestCase):

    # The twofactor_enabled being None indicates that the gargoyle flag
    # will be selective for the test user, thus the assertion should be the
    # same as those for WithTwoFactorEnabledWithDeviceTestCase (parent).
    twofactor_enabled = None  # will do some per user, selective, setup

    def setUp(self):
        super(AccountTemplateTestCase, self).setUp()
        condition_set = ('identityprovider.gargoyle.AccountConditionSet('
                         'identityprovider.account)')
        self.conditionally_enable_flag(
            'TWOFACTOR', 'email', self.login_email, condition_set)

    def get_devices_fieldset(self):
        response = self.client.get(AccountEditTestCase.url)
        self.assertEqual(response.status_code, 200)

        tree = PyQuery(response.content)
        return tree.find('[data-qa-id="edit_fieldsets"] fieldset')

    def test_with_flag_for_user(self):
        fieldset = self.get_devices_fieldset()
        self.assertEqual(len(fieldset), 2)

        self.assertIsNotNone(fieldset.find(
            '[data-qa-id="personal_details"]'
        ))
        self.assertIsNotNone(fieldset.find(
            '[data-qa-id="authentication_devices"]'
        ))

    def test_without_flag_for_user(self):
        person = self.factory.make_person()
        email = EmailAddress.objects.get(email=self.login_email)
        email.account = None
        email.lp_person = person
        email.save()

        fieldset = self.get_devices_fieldset()
        self.assertEqual(len(fieldset), 0)


class VerifyEmailWarningTestCase(AuthenticatedTestCase):

    url = reverse('account-edit')

    def setUp(self):
        super(VerifyEmailWarningTestCase, self).setUp()
        self.switch = switches(ALLOW_UNVERIFIED=True)
        self.switch.patch()
        self.addCleanup(self.switch.unpatch)

    def assert_email_shown(self, response):
        email_input = PyQuery(response.content).find(
            'input[type="text"][disabled="true"]')
        self.assertEqual(len(email_input), 1)
        self.assertEqual(email_input[0].get('value'),
                         self.account.preferredemail.email)

    def assert_verify_warning(self, response):
        tree = PyQuery(response.content)
        # check warning
        warning = tree.find('div#unverified_email_warning')
        self.assertEqual(len(warning), 1)
        # check verify email link
        links = warning.find('a')
        self.assertEqual(len(links), 1)
        link = links[0]
        email = self.account.preferredemail
        verify_link = '%s?id=%d' % (reverse('verify_email'), email.id)
        self.assertEqual(link.get('href'), verify_link)
        # check verify email text
        self.assertIn('You have not verified your email address %s' % email,
                      warning.text())
        self.assert_email_shown(response)

    def assert_no_verify_warning(self, response):
        tree = PyQuery(response.content)
        warning = tree.find('div#unverified_email_warning')
        self.assertEqual(len(warning), 0)

    def test_verify_email_link_available(self):
        self.account.emailaddress_set.update(status=EmailStatus.NEW)
        response = self.client.get(self.url)
        self.assert_verify_warning(response)

    def test_verify_email_link_is_not_shown(self):
        assert self.account.preferredemail.is_verified
        response = self.client.get(self.url)
        # check warning
        self.assert_no_verify_warning(response)

    def test_verify_email_link_is_not_shown_right_after_registration(self):
        self.account.emailaddress_set.update(status=EmailStatus.NEW)
        assert self.account.verified_emails().count() == 0

        # redirect to edit view from 'new_account'
        referer = urljoin(settings.SSO_ROOT_URL, reverse('new_account'))
        response = self.client.get(self.url, HTTP_REFERER=referer)
        self.assert_no_verify_warning(response)
        self.assert_email_shown(response)

    def test_verify_email_link_is_shown_referer_suffix(self):
        self.account.emailaddress_set.update(status=EmailStatus.NEW)
        assert self.account.verified_emails().count() == 0

        referer = reverse('new_account')
        response = self.client.get(self.url, HTTP_REFERER=referer)
        self.assert_verify_warning(response)

    def test_verify_email_link_is_shown_referer_prefix(self):
        self.account.emailaddress_set.update(status=EmailStatus.NEW)
        assert self.account.verified_emails().count() == 0

        referer = settings.SSO_ROOT_URL
        response = self.client.get(self.url, HTTP_REFERER=referer)
        self.assert_verify_warning(response)

    def test_verify_email_link_is_shown_other_referer(self):
        self.account.emailaddress_set.update(status=EmailStatus.NEW)
        assert self.account.verified_emails().count() == 0

        referer = 'http://example.com'
        response = self.client.get(self.url, HTTP_REFERER=referer)
        self.assert_verify_warning(response)


class AccountDeletionViewTestCase(AuthenticatedTestCase):

    def test_delete_email_get_form(self):
        email = self.account.emailaddress_set.create(
            email='test@test.com', status=EmailStatus.NEW)
        r = self.client.get(reverse('delete_email'), {'id': email.id})
        self.assertTemplateUsed(r, 'account/delete_email.html')

    def test_delete_email_when_submiting_form(self):
        email = self.account.emailaddress_set.create(
            email='test@test.com', status=EmailStatus.NEW)
        # Due to limitation in Django 1.0 you can't pass directly GET arguments
        # to post method, that's why you need to use QUERY_STRING, this is
        # unnecessary in Django 1.1
        r = self.client.post(reverse('delete_email'),
                             QUERY_STRING='id=%s' % email.id)
        self.assertRedirects(r, reverse('account-emails'))


class AccountDeactivationViewTestCase(AuthenticatedTestCase):

    def setUp(self):
        super(AccountDeactivationViewTestCase, self).setUp()
        self._refresh_account()

        # make sure to enable the views
        patched = patch_settings(TESTING=True)
        patched.start()
        self.addCleanup(patched.stop)

    def _refresh_account(self):
        email = EmailAddress.objects.get(email__iexact=self.login_email)
        self.account = email.account

    def test_deactivate_account(self):
        # make sure we have a preferredemail
        email = self.account.emailaddress_set.all()[0]
        email.status = EmailStatus.VALIDATED
        email.save()
        self.account.preferredemail = email

        # deactivate account
        r = self.client.post('/+deactivate')
        self.assertRedirects(r, reverse('deactivated'))

        # re-request account object from db
        self._refresh_account()

        # test account has been deactivated
        self.assertEqual(AccountStatus.DEACTIVATED, self.account.status)
        for email in self.account.emailaddress_set.all():
            self.assertEqual(EmailStatus.NEW, email.status)

    def test_deactivate_with_token(self):
        token = 'a' * 16
        # This strange dance with session is necessary to overcome way in which
        # test.Client returns session (recreating it on every Client.session
        # access)
        session = self.client.session
        session[token] = 'raw_orequest content'
        session.save()

        # deactivate account
        r = self.client.post('/%s/+deactivate' % token)
        self.assertRedirects(r, reverse('deactivated'))

        # test token is preserved
        self.assertEqual(self.client.session.get(token),
                         'raw_orequest content')

    def test_deactivate_account_when_testing_is_disabled(self):
        with patch_settings(TESTING=False):
            response = self.client.get(reverse('account_deactivate'))
            self.assertEqual(response.status_code, 404)


@skipUnless(settings.BRAND == 'ubuntu',
            "Applications only for ubuntu brand.""")
class ApplicationsTestCase(AuthenticatedTestCase):

    def test_applications_page_is_rendered_using_right_template(self):
        r = self.client.get(reverse('applications'))
        self.assertTemplateUsed(r, 'account/applications.html')

    def test_account_without_applications_does_not_renders_token_table(self):
        r = self.client.get(reverse('applications'))
        # since user is logged in, there should be the web login token
        self.assertContains(r, SESSION_TOKEN_NAME)

    def test_revoking_token_removes_it_from_being_displayed(self):
        token_1 = self.account.create_oauth_token("Token-1")
        token_2 = self.account.create_oauth_token("Token-2")

        r = self.client.get(reverse('applications'))

        self.assertContains(r, "Token-1")
        self.assertContains(r, "Token-2")

        self.client.post(reverse('applications'), {'token_id': token_2.token})

        r = self.client.get(reverse('applications'))

        self.assertNotContains(r, token_2.token)

        token_1.delete()

    def test_revoking_token_which_does_not_belogs_to_an_account(self):
        account = self.factory.make_account(email="foo@x.com")
        token = account.create_oauth_token("Token")

        r = self.client.post(reverse('applications'),
                             {'token_id': token.token})

        self.assertRedirects(r, reverse('applications'))
        self.assertEqual(Token.objects.filter(token=token.token).count(), 1)


class InvalidateEmailTestCase(SSOBaseTestCase):

    email = 'foo@example.com'
    token = '123456'
    url_name = 'invalidate_email'
    url = reverse(url_name, kwargs=dict(email_address=email, authtoken=token))

    def setUp(self):
        super(InvalidateEmailTestCase, self).setUp()

        # email invalidation makes sense only when ALLOW_UNVERIFIED is enabled
        switch = switches(ALLOW_UNVERIFIED=True)
        switch.patch()
        self.addCleanup(switch.unpatch)

        p = mock.patch('webui.views.account.logger')
        self.mock_logger = p.start()
        self.addCleanup(p.stop)

        self.account = self.factory.make_account(
            email=self.email, email_validated=False,
            password_encrypted=False, password=DEFAULT_USER_PASSWORD,
        )
        self.emailaddress = self.account.emailaddress_set.get()
        assert self.emailaddress.status == EmailStatus.NEW
        self.authtoken = AuthToken.objects.create(
            email=self.email, token=self.token,
            token_type=TokenType.INVALIDATEEMAIL)

    def assert_no_changes(self):
        emailaddress = EmailAddress.objects.get(id=self.emailaddress.id)
        self.assertEqual(emailaddress.status, EmailStatus.NEW)
        self.assertTrue(self.account.is_active)
        self.assertFalse(self.mock_logger.called)

    def assert_happy_path(self, response, expected_logging=None):
        self.assertTemplateUsed(response, 'account/invalidate_email.html')
        tree = PyQuery(response.content)
        submit_buttons = tree.find('button[type="submit"]')
        self.assertEqual(len(submit_buttons), 0)
        self.assertContains(response, self.email)
        self.assertContains(response, 'was successfully invalidated')

        if expected_logging is None:
            self.mock_logger.info.assert_called_once_with(mock.ANY, self.email)
        else:
            self.assertEqual(self.mock_logger.mock_calls, expected_logging)

    def test_missing_params(self):
        self.assertRaises(NoReverseMatch, reverse, self.url_name)

    def test_no_authtoken(self):
        self.assertRaises(NoReverseMatch, reverse, self.url_name,
                          kwargs=dict(email=self.email))

    def test_no_email(self):
        self.assertRaises(NoReverseMatch, reverse, self.url_name,
                          kwargs=dict(authtoken=self.token))

    def test_nonexisting_authtoken(self):
        AuthToken.objects.all().delete()
        assert AuthToken.objects.count() == 0

        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 404)
        self.assert_no_changes()

    def test_bad_authtoken_type(self):
        for t, _ in TokenType._get_choices():
            if t == TokenType.INVALIDATEEMAIL:
                continue  # will test in the happy path

            AuthToken.objects.all().delete()
            token = AuthToken(
                email=self.email, token=self.token, token_type=t)
            token.save()
            self.addCleanup(token.delete)

            response = self.client.get(self.url)
            self.assertEqual(response.status_code, 404)
            self.assert_no_changes()

    def test_bad_authtoken_email(self):
        self.authtoken.email = self.email + '.foo'
        self.authtoken.save()

        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 404)
        self.assert_no_changes()

    def test_bad_authtoken_consumed(self):
        self.authtoken.date_consumed = datetime.now()
        self.authtoken.save()

        response = self.client.get(self.url)
        self.assertRedirects(response, reverse('bad_token'))
        self.assert_no_changes()

    def test_nonexisting_email(self):
        EmailAddress.objects.all().delete()
        assert EmailAddress.objects.count() == 0

        response = self.client.post(self.url)

        log_msg = ('Received a request to invalidate email %r, but a matching '
                   'EmailAddress does not exist in the system.')
        expected_logging = [mock.call.info(log_msg, self.email)]
        self.assert_happy_path(response, expected_logging)

    def test_shows_confirmation(self):
        response = self.client.get(self.url)
        # response is a confirmation page
        self.assertTemplateUsed(response,
                                'account/confirm_email_invalidation.html')
        tree = PyQuery(response.content)
        submit_buttons = tree.find('button[type="submit"]')
        self.assertEqual(len(submit_buttons), 1)

        # now, submit the confirmation and assert over the happy path
        response = self.client.post(self.url)
        self.assert_happy_path(response)

    def test_happy_path(self):
        response = self.client.post(self.url)
        self.assert_happy_path(response)

    def test_happy_path_kills_tokens(self):
        account = self.account
        account.get_or_create_oauth_token('token 1')
        account.get_or_create_oauth_token('token 2')

        user = User.objects.get(username=account.openid_identifier)
        consumer = Consumer.objects.get(user=user)
        assert consumer.token_set.count() == 2

        response = self.client.post(self.url)

        expected_logging = [mock.call.info(mock.ANY, self.email),
                            mock.call.info(mock.ANY, self.email)]
        self.assert_happy_path(response, expected_logging)
        self.assertEqual(consumer.token_set.count(), 0)

    def test_email_without_account(self):
        # the email address has to be linked to either an account or a person
        # so removing the account forces us to link to a person
        person = self.factory.make_person()
        self.emailaddress.account = None
        self.emailaddress.lp_person = person
        self.emailaddress.save()

        response = self.client.post(self.url)
        self.assert_happy_path(response)
        self.mock_logger.warning.assert_called_once_with(
            'Received a request to invalidate email %r, but the email\'s '
            'account is None.', self.email)

    def test_email_invalidated(self):
        response = self.client.post(self.url)

        self.assert_happy_path(response)
        # reload email from DB
        emails = EmailAddress.objects.filter(id=self.emailaddress.id)
        self.assertFalse(emails.exists())
        email = InvalidatedEmailAddress.objects.get(
            email=self.emailaddress.email, account=self.account)
        self.assertTrue(email)
        self.mock_logger.info.assert_called_once_with(mock.ANY, self.email)

    def test_token_consumed(self):
        assert self.authtoken.date_consumed is None
        response = self.client.post(self.url)

        self.assert_happy_path(response)
        authtoken = AuthToken.objects.get(id=self.authtoken.id)
        self.assertIsNotNone(authtoken.date_consumed)

    def test_other_tokens_consumed(self):
        # create some tokens for some email addresses
        types = (
            TokenType.VALIDATEEMAIL,
            TokenType.PASSWORDRECOVERY,
            TokenType.NEWPERSONLESSACCOUNT,
        )
        other_email = 'aaa@example.com'
        assert other_email != self.email
        for t in types:
            at = AuthToken.objects.create(token_type=t, email=self.email)
            assert at.active
            at = AuthToken.objects.create(token_type=t, email=other_email)
            assert at.active

        self.client.post(self.url)

        for at in AuthToken.objects.all():
            self.assertEqual(at.active, at.email != self.email)

    def test_other_tokens_date_consumed_not_overwritten(self):
        at = AuthToken.objects.create(token_type=TokenType.PASSWORDRECOVERY,
                                      email=self.email)
        at.consume()
        date_consumed = at.date_consumed

        self.client.post(self.url)
        # reload token
        at = AuthToken.objects.get(id=at.id)
        self.assertEqual(at.date_consumed, date_consumed)

    def test_account_logged_out_after_invalidation(self):
        emails = self.account.emailaddress_set
        assert emails.exclude(status=EmailStatus.NEW).count() == 0

        assert self.client.login(username=self.email,
                                 password=DEFAULT_USER_PASSWORD)

        with mock.patch('django.contrib.auth.logout') as mock_logout:
            # user is now logged in with an address that will be invalidated
            response = self.client.post(self.url)
            mock_logout.assert_called_once_with(response.context['request'])

    def test_no_notification(self):
        assert self.account.emailaddress_set.count() == 1

        self.client.post(self.url)

        self.assertEqual(len(mail.outbox), 0)

    def test_other_email_is_notified(self, notified_email=None):
        # create another NEW email for this account
        email = self.factory.make_email_for_account(
            account=self.account, status=EmailStatus.NEW)

        if notified_email is None:
            assert self.account.verified_emails().count() == 0
            notified_email = email

        self.client.post(self.url)
        # reload account
        self.account = Account.objects.get(id=self.account.id)

        self.assertEqual(len(mail.outbox), 1)
        email = mail.outbox[0]
        self.assertEqual(email.to, [notified_email.email])
        for msg in (self.email, 'removed from your account'):
            self.assertIn(msg, email.subject)
        for msg in (
                self.email,
                'You will no longer be able to login to your account using',
                notified_email.email):
            self.assertIn(msg, email.body)

    def test_new_email_is_not_notified_if_validated_email_available(self):
        # create a VALIDATED EMAIL for this account
        email = self.factory.make_email_for_account(
            account=self.account, status=EmailStatus.VALIDATED)
        self.test_other_email_is_notified(notified_email=email)
