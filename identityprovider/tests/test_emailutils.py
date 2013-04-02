# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).
from urlparse import urljoin

from django.conf import settings
from django.core import mail
from django.core.urlresolvers import reverse
from django.template.loader import render_to_string
from django.utils import unittest
from gargoyle.testutils import gargoyle, switches
from mock import patch

from identityprovider.emailutils import (
    format_address,
    send_action_applied_notice,
    send_action_required_warning,
    send_branded_email,
    send_impersonation_email,
    send_invalidation_email_notice,
    send_invitation_after_password_reset,
    send_new_user_email,
    send_password_reset_email,
    send_preferred_changed_notification,
    send_templated_email,
    send_validation_email_request,
)
from identityprovider.models import Account, AuthToken, EmailAddress
from identityprovider.models.const import EmailStatus, TokenType
from identityprovider.tests.utils import (
    patch_settings,
    SSOBaseTestCase,
    SSOBaseUnittestTestCase,
)
from identityprovider.utils import get_current_brand


class FormatAddressTestCase(unittest.TestCase):
    def test_address_and_name(self):
        result = format_address('foo@bar.com', 'Name')
        self.assertEqual(result, 'Name <foo@bar.com>')

    def test_address_empty_name(self):
        result = format_address('foo@bar.com', '')
        self.assertEqual(result, 'foo@bar.com')

    def test_address_no_name(self):
        result = format_address('foo@bar.com')
        self.assertEqual(result, 'foo@bar.com')

    def test_unicode_name(self):
        result = format_address('foo.bar@canonical.com', u'F\xc3\xb4 Bar')
        expected = '=?utf-8?b?RsODwrQgQmFy?= <foo.bar@canonical.com>'
        self.assertEqual(result, expected)

    def test_unicode_name_bytestring(self):
        result = format_address('foo.bar@canonical.com', 'F\xc3\xb4 Bar')
        expected = '=?utf-8?q?F=C3=B4_Bar?= <foo.bar@canonical.com>'
        self.assertEqual(result, expected)

    def test_unicode_addr(self):
        result = format_address(u'f\xc3\xb4.bar@canonical.com', u'Foo Bar')
        expected = 'Foo Bar <f\xc3\x83\xc2\xb4.bar@canonical.com>'
        self.assertEqual(result, expected)

    def test_unicode_addr_no_name(self):
        result = format_address(u'f\xc3\xb4.bar@canonical.com')
        expected = 'f\xc3\x83\xc2\xb4.bar@canonical.com'
        self.assertEqual(result, expected)

    def test_quoting(self):
        result = format_address('foo.bar@canonical.com', 'Foo [Baz] Bar')
        self.assertEqual(result, '"Foo \\[Baz\\] Bar" <foo.bar@canonical.com>')

    def test_long_name(self):
        result = format_address('long.name@example.com', 'a ' * 100)
        self.assertFalse('\n' in result)


class SendTemplatedEmailTestCase(SSOBaseUnittestTestCase):
    noreply = 'noreply@example.com'

    def setUp(self):
        super(SendTemplatedEmailTestCase, self).setUp()

        p = patch_settings(
            NOREPLY_FROM_ADDRESS=self.noreply,
        )
        p.start()
        self.addCleanup(p.stop)
        self.mock_send = self._apply_patch(
            'identityprovider.emailutils.send_mail'
        )
        self.mock_render = self._apply_patch(
            'identityprovider.emailutils.render_to_string'
        )

    def test_no_from(self):
        send_templated_email("", "", {}, '')
        self.assertEqual(
            self.mock_send.call_args[0][-2],
            self.noreply
        )

    def test_single_email(self):
        send_templated_email("", "", {}, 'test@abc.com')
        self.assertEqual(
            self.mock_send.call_args[0][-1],
            ['test@abc.com']
        )

    def test_multiple_emails(self):
        send_templated_email("", "", {}, ['test@abc.com', 'test2@abc.com'])
        self.assertEqual(
            self.mock_send.call_args[0][-1],
            ['test@abc.com', 'test2@abc.com']
        )


class SendBrandedEmailTestCase(SSOBaseUnittestTestCase):
    noreply = 'noreply@example.com'

    def setUp(self):
        super(SendBrandedEmailTestCase, self).setUp()

        p = patch_settings(
            NOREPLY_FROM_ADDRESS=self.noreply,
            BRAND_DESCRIPTIONS={get_current_brand(): 'BRAND'},
        )
        p.start()
        self.addCleanup(p.stop)
        self.mock_send = self._apply_patch(
            'identityprovider.emailutils.send_mail'
        )
        self.mock_render = self._apply_patch(
            'identityprovider.emailutils.render_to_string'
        )
        self.mock_context = self._apply_patch(
            'identityprovider.emailutils.RequestContext'
        )

    def test_branded_email(self, context=None):
        if context is None:
            context = {}
        send_branded_email("subject", "template", context, 'test@abc.com')
        self.assertEqual(
            self.mock_send.call_args[0][-2],
            'BRAND <noreply@example.com>'
        )
        self.assertEqual(self.mock_send.call_args[0][0], 'BRAND: subject')
        self.mock_context.assert_called_once_with(None, context)
        self.mock_render.assert_called_once_with(
            'template', context_instance=self.mock_context.return_value)

    def test_branded_email_with_context(self):
        self.test_branded_email(context={'foo': 'bar'})

    def test_branded_email_no_from(self):
        send_branded_email("", "", {}, 'test@abc.com')
        self.assertEqual(
            self.mock_send.call_args[0][-2],
            'BRAND <noreply@example.com>'
        )


class SendEmailTestCase(SSOBaseTestCase):

    email = 'testing@canonical.com'
    status = EmailStatus.VALIDATED  # the EmailStatus of the target email
    redirection_url = 'http://foo.example.com'
    template_string_if_invalid = 'TEMPLATE_STRING_IF_INVALID'
    brand = 'ubuntu'
    brand_desc = 'Foo Bar Baz'
    brand_url = 'http://foobarbaz.amazing'

    def setUp(self):
        super(SendEmailTestCase, self).setUp()
        self.account = self.factory.make_account(email='test@canonical.com')
        self.factory.make_email_for_account(
            email='testing@canonical.com', status=EmailStatus.VALIDATED,
            account=self.account)
        self.factory.make_email_for_account(
            email='testtest@canonical.com', status=EmailStatus.NEW,
            account=self.account)
        self.factory.make_email_for_account(
            email='testtesttest@canonical.com',
            account=self.account).invalidate()

        p = patch_settings(
            BRAND_DESCRIPTIONS={self.brand: self.brand_desc},
            BRAND=self.brand,
            TEMPLATE_STRING_IF_INVALID=self.template_string_if_invalid,
            SSO_ROOT_URL=self.brand_url,
        )
        p.start()
        self.addCleanup(p.stop)

        # Do not mock send_branded_email since we need to confirm that no
        # variable gets unrendered in the email.

        if self.status is not None:
            emailaddress = EmailAddress.objects.get(email=self.email)
            assert emailaddress.status == self.status
        else:
            assert EmailAddress.objects.filter(email=self.email).count() == 0
        assert AuthToken.objects.all().count() == 0

    def assert_tokens(self, target_email=None, requester_email=None,
                      displayname=None, password=None, tokens_count=1,
                      **kwargs):
        tokens = AuthToken.objects.all()
        self.assertEqual(tokens.count(), tokens_count)

        if target_email is None:
            target_email = self.email

        redirection_url = kwargs.get('redirection_url', self.redirection_url)

        for token in tokens:
            self.assertEqual(token.requester, self.account)
            self.assertEqual(token.requester_email, requester_email)
            self.assertEqual(token.email, target_email)
            self.assertEqual(token.redirection_url, redirection_url)
            if token.token_type != TokenType.INVALIDATEEMAIL:
                self.assertEqual(token.displayname, displayname)
                self.assertEqual(token.password, password)
            else:
                self.assertIsNone(token.displayname)
                self.assertIsNone(token.password)

    def get_context(self, token_type):
        # get just-created tokens
        token = AuthToken.objects.get(token_type=token_type)
        requester = getattr(self.account, 'displayname', token.displayname)
        context = {
            'requester': requester,
            'requester_email': token.requester_email,
            'brand_description': self.brand_desc,
            'toaddress': self.email,
            'token': token.token,
            'token_url': token.absolute_url,
        }

        account = Account.objects.get_by_email(self.email)
        if gargoyle.is_active('ALLOW_UNVERIFIED', account):
            # If the account does not have any validated/preferred email
            # address, ensure an invalidation token was also created
            if self.account and self.account.verified_emails().count() == 0:
                invalidate_token = AuthToken.objects.get(
                    token_type=TokenType.INVALIDATEEMAIL)
                context['invalidate_email_url'] = invalidate_token.absolute_url

        return context

    def assert_email_properly_formatted(self, subject, template, context=None,
                                        token_type=None, **kwargs):
        if context is None:
            context = self.get_context(token_type)
        context.update(kwargs)

        self.assertEqual(len(mail.outbox), 1)
        email = mail.outbox[0]
        self.assertEqual(email.subject,
                         self.brand_desc + ': ' + subject)
        self.assertEqual(render_to_string(template, context), email.body)
        self.assertNotIn(self.template_string_if_invalid, email.body)

        # XXX: due to https://code.djangoproject.com/ticket/19915
        # the setting TEMPLATE_STRING_IF_INVALID will not be used even if the
        # context does not provide an expected variable to be defined, so we
        # need to do this ugly yet effective test to ensure all variables are
        # defined:
        self.assertNotIn('  ', email.body)

        invalidate_msg = ('If you wish to report this email being incorrectly '
                          'used, please click the following link:')
        invalidate_url = context.get('invalidate_email_url', '')
        if invalidate_url:
            self.assertIn(invalidate_msg, email.body)
            self.assertIn(invalidate_url, email.body)
        else:
            self.assertNotIn(invalidate_msg, email.body)

    def test_send_impersonation_email(self):
        send_impersonation_email(self.email)

        url = urljoin(self.brand_url, reverse('forgot_password'))
        context = {
            'forgotten_password_url': url,
            'brand_description': self.brand_desc,
            'to_email': self.email,
        }
        self.assert_email_properly_formatted(
            'Warning', 'email/impersonate-warning.txt', context)
        email = mail.outbox[0]
        self.assertIn("If it wasn't you, no need to worry. Your account is "
                      "safe and there is nothing you need to do.",
                      email.body)

    def test_send_new_user_email_no_platform(self):
        send_new_user_email(
            self.account, self.email, self.redirection_url)

        self.assert_tokens()
        self.assert_email_properly_formatted(
            'Finish your registration', 'email/welcome.txt',
            token_type=TokenType.VALIDATEEMAIL)

    @patch('identityprovider.emailutils.logging')
    def test_send_new_user_email_invalid_platform(self, mock_logger):
        send_new_user_email(
            self.account, self.email, self.redirection_url,
            platform='foo')

        self.assert_tokens()
        self.assert_email_properly_formatted(
            'Finish your registration', 'email/welcome.txt',
            token_type=TokenType.VALIDATEEMAIL)
        mock_logger.error.assert_called_once_with(
            'Invalid platform requested during send_new_user_email: %s. '
            'Using default platform ("all").', 'foo')

    def test_send_new_user_email_platform_desktop(self):
        send_new_user_email(
            self.account, self.email, self.redirection_url,
            platform='desktop')

        self.assert_tokens()
        self.assert_email_properly_formatted(
            'Finish your registration', 'email/desktop-newuser.txt',
            token_type=TokenType.VALIDATEEMAIL)

    def test_send_new_user_email_platform_mobile(self):
        self.account = None
        send_new_user_email(
            self.account, self.email, self.redirection_url,
            platform='mobile')

        self.assert_tokens()
        self.assert_email_properly_formatted(
            'Finish your registration', 'email/mobile-newuser.txt',
            token_type=TokenType.NEWPERSONLESSACCOUNT)

    def test_send_new_user_email_platform_web(self):
        self.account = None
        send_new_user_email(
            self.account, self.email, self.redirection_url,
            platform='web')

        self.assert_tokens()
        self.assert_email_properly_formatted(
            'Finish your registration', 'email/web-newuser.txt',
            token_type=TokenType.NEWPERSONLESSACCOUNT)

    def test_send_new_user_email_kwargs_are_passed(self):
        self.account = None
        send_new_user_email(
            self.account, self.email, self.redirection_url,
            platform='web', displayname='foo', password='test')

        self.assert_tokens(displayname='foo', password='test')
        self.assert_email_properly_formatted(
            'Finish your registration', 'email/web-newuser.txt',
            token_type=TokenType.NEWPERSONLESSACCOUNT)

    def test_send_password_reset_email_with_redirection_url(self):
        send_password_reset_email(
            self.account, self.email, self.redirection_url)

        self.assert_tokens(requester_email=self.email)
        self.assert_email_properly_formatted(
            'Forgotten Password', 'email/forgottenpassword.txt',
            token_type=TokenType.PASSWORDRECOVERY)

    def test_send_password_reset_email_no_redirection_url(self):
        send_password_reset_email(self.account, self.email)

        self.assert_tokens(requester_email=self.email, redirection_url=None)
        self.assert_email_properly_formatted(
            'Forgotten Password', 'email/forgottenpassword.txt',
            token_type=TokenType.PASSWORDRECOVERY)

    def test_send_validation_email_request_with_preferred_email(self):
        assert self.account.preferredemail is not None

        send_validation_email_request(
            self.account, self.email, self.redirection_url)

        email = self.account.preferredemail.email
        self.assert_tokens(requester_email=email)
        self.assert_email_properly_formatted(
            'Validate your email address', 'email/validate-email.txt',
            token_type=TokenType.VALIDATEEMAIL)

    def test_send_validation_email_request_no_preferredemail(self):
        self.account._preferredemail = None
        assert self.account.preferredemail is None

        send_validation_email_request(
            self.account, self.email, self.redirection_url)

        self.assert_tokens()
        self.assert_email_properly_formatted(
            'Validate your email address', 'email/validate-email.txt',
            token_type=TokenType.VALIDATEEMAIL)

    def test_send_validation_email_request_no_redirection_url(self):
        send_validation_email_request(self.account, self.email)

        email = self.account.preferredemail.email
        self.assert_tokens(requester_email=email, redirection_url=None)
        self.assert_email_properly_formatted(
            'Validate your email address', 'email/validate-email.txt',
            token_type=TokenType.VALIDATEEMAIL)

    def _assert_send_invalidation_email_notice(self):
        invalidated_email = 'invalid@example.com'
        send_invalidation_email_notice(self.account, invalidated_email)

        verify_emails_link = urljoin(settings.SSO_ROOT_URL,
                                     reverse('account-emails'))
        context = dict(
            brand_description=self.brand_desc,
            display_name=self.account.displayname,
            invalidated_email=invalidated_email,
            to_email=self.account.preferredemail,
        )
        if self.account.unverified_emails().count() > 0:
            context['verify_emails_link'] = verify_emails_link
        subject = 'The email address {email} was removed from your account'
        self.assert_email_properly_formatted(
            subject.format(email=invalidated_email),
            'email/email-invalidated.txt',
            context=context)

        content = mail.outbox[0].body
        optionals = ('We strongly recommend you take the time to verify any '
                     'unverified email address by visiting this link',
                     verify_emails_link)
        for optional in optionals:
            if self.account.unverified_emails().count() == 0:
                self.assertNotIn(optional, content)
            else:
                self.assertIn(optional, content)

    def test_send_invalidation_email_notice_with_verify_email_link(self):
        assert self.account.unverified_emails().count() > 0
        self._assert_send_invalidation_email_notice()

    def test_send_invalidation_email_notice_no_verify_email_link(self):
        self.account.emailaddress_set.update(status=EmailStatus.VALIDATED)
        assert self.account.unverified_emails().count() == 0
        self._assert_send_invalidation_email_notice()

    def test_send_preferred_changed_notification(self):
        new_preferred = 'a@foo.com'
        send_preferred_changed_notification(self.email, new_preferred)

        context = {
            'brand_description': self.brand_desc,
            'new_preferred': new_preferred,
        }
        self.assert_email_properly_formatted(
            'E-mail change notification', 'email/preferred-changed.txt',
            context=context)

    def test_send_invitation_after_password_reset(self):
        url = urljoin(self.brand_url, reverse('new_account'))
        send_invitation_after_password_reset(self.email)

        context = {
            'brand_description': self.brand_desc,
            'email': self.email, 'signup': url,
        }
        self.assert_email_properly_formatted(
            'Password reset request', 'email/invitation.txt', context=context)

    @switches(ALLOW_UNVERIFIED=True)
    def test_send_action_required_warning(self, action='suspend',
                                          result='suspended'):
        # since this applies to account with no validated nor preferred email,
        # remove those:
        EmailAddress.objects.filter(
            account=self.account, status__in=[EmailStatus.PREFERRED,
                                              EmailStatus.VALIDATED]).delete()
        assert self.account.verified_emails().count() == 0
        url = urljoin(self.brand_url, reverse('account-emails'))

        send_action_required_warning(
            self.account, days_of_warning=8, action=action)

        # tokens will always be 2, since we need the validate email token *and*
        # the invalidate email
        self.assert_tokens(
            target_email=self.account.preferredemail.email,
            redirection_url=None, tokens_count=2)
        self.assert_email_properly_formatted(
            'Account to be %s - action required' % result,
            'email/account-action-required.txt',
            token_type=TokenType.VALIDATEEMAIL,
            created=self.account.date_created,
            emails_url=url, days_of_warning=8, action=action)

    @switches(ALLOW_UNVERIFIED=True)
    def test_send_action_applied_notice(self, action='suspend',
                                        result='suspended'):
        # since this applies to account with no validated nor preferred email,
        # remove those:
        EmailAddress.objects.filter(
            account=self.account, status__in=[EmailStatus.PREFERRED,
                                              EmailStatus.VALIDATED]).delete()

        send_action_applied_notice(
            self.account.preferredemail.email, self.account.displayname,
            days_of_warning=8, action=action)

        context = dict(
            brand_description=self.brand_desc,
            display_name=self.account.displayname,
            days_of_warning=8, action=action,
        )
        self.assert_email_properly_formatted(
            'Account %s' % result, 'email/account-%s-applied.txt' % action,
            context=context)

    @switches(ALLOW_UNVERIFIED=True)
    def test_send_action_required_warning_delete(self):
        self.test_send_action_required_warning(action='delete',
                                               result='deleted')

    @switches(ALLOW_UNVERIFIED=True)
    def test_send_action_applied_notice_delete(self):
        self.test_send_action_applied_notice(action='delete',
                                             result='deleted')


class SendEmailOtherBrandTestCase(SendEmailTestCase):
    """Confirm that the rest of the brands have all the needed templates."""

    brand = 'launchpad'


class SendEmailToPreferredAddressTestCase(SendEmailTestCase):

    email = 'test@canonical.com'
    status = EmailStatus.PREFERRED

    # all the same asserts as parent, PREFERRED behaves just like VALIDATED


class SendEmailToNewAddressTestCase(SendEmailTestCase):

    email = 'testtest@canonical.com'
    status = EmailStatus.NEW

    # assert changes since the invalidation link has to added to emails

    def get_context(self, token_type=None):
        context = super(SendEmailToNewAddressTestCase, self).get_context(
            token_type)
        account = Account.objects.get_by_email(self.email)
        if gargoyle.is_active('ALLOW_UNVERIFIED', account):
            invalidate_token = AuthToken.objects.get(
                token_type=TokenType.INVALIDATEEMAIL)
            context['invalidate_email_url'] = invalidate_token.absolute_url
        return context


class SendEmailToUnknownAddressTestCase(SendEmailToNewAddressTestCase):

    email = 'newemail@foo.com'
    status = None

    # all the same asserts as parent, unknown email behaves just like NEW
