# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from datetime import datetime, timedelta

from django.conf import settings
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.test import TestCase

from gargoyle.testutils import switches
from gargoyle import gargoyle

from mock import patch
from oauth_backend.models import Consumer


from identityprovider.login import (
    AuthenticationError,
    AccountDeactivated,
    AccountSuspended,
    authenticate_user,
)
from identityprovider.models.account import (
    Account,
    AccountPassword,
    AccountQuerySet,
)
from identityprovider.models import account as a
from identityprovider.models.emailaddress import EmailAddress
from identityprovider.models.const import (
    AccountStatus,
    AccountCreationRationale,
    EmailStatus,
)
from identityprovider.readonly import ReadOnlyManager
from identityprovider.utils import encrypt_launchpad_password, generate_salt
from identityprovider.tests import DEFAULT_USER_PASSWORD
from identityprovider.tests.utils import (
    TeamConditionSelectiveMixin,
    SSOBaseTestCase,
)


class MockBackend(object):

    def __init__(self, value):
        self.value = value

    def has_module_perms(self, account, app_label):
        return self.value

    def has_perm(self, account, perm):
        return self.value


class AccountQuerySetTestCase(SSOBaseTestCase):

    def setUp(self):
        super(AccountQuerySetTestCase, self).setUp()
        self.qs = AccountQuerySet(model=Account)

    def test_verified_list_only_verified_accounts(self):
        accounts = self.qs.verified()
        for account in accounts:
            emails = account.emailaddress_set.all()
            self.assertTrue(any([email.is_verified for email in emails]))


class AccountManagerTestCase(SSOBaseTestCase):

    def test_objects_get_by_email_fails(self):
        account = Account.objects.get_by_email('somethin@which.not.exists.com')

        self.assertTrue(account is None)

    def test_create_account_with_invalid_password(self):
        salt = generate_salt()
        kwargs = dict(
            displayname='displayname', email_address='email@host.local',
            password='test', salt=salt,
            creation_rationale=AccountCreationRationale.USER_CREATED,
        )
        self.assertRaises(ValidationError, Account.objects.create_account,
                          **kwargs)

    def test_create_account_with_invalid_email_address(self):
        salt = generate_salt()
        kwargs = dict(
            displayname='displayname', email_address='not_an_email',
            password=DEFAULT_USER_PASSWORD, salt=salt,
            creation_rationale=AccountCreationRationale.USER_CREATED,
        )
        self.assertRaises(ValidationError, Account.objects.create_account,
                          **kwargs)

    def test_create_account_with_rationale(self):
        salt = generate_salt()
        account = Account.objects.create_account(
            displayname='displayname', email_address='email@host.local',
            password=DEFAULT_USER_PASSWORD,
            creation_rationale=AccountCreationRationale.USER_CREATED,
            salt=salt,
        )

        self.assertEqual(account.displayname, 'displayname')
        self.assertEqual(account.creation_rationale,
                         AccountCreationRationale.USER_CREATED)
        self.assertEqual(account.status, AccountStatus.ACTIVE)

        emails = EmailAddress.objects.filter(account=account)
        self.assertEqual(emails.count(), 1)
        email = emails[0]
        self.assertEqual(email.email, 'email@host.local')
        self.assertEqual(email.status, EmailStatus.PREFERRED)

        passwords = AccountPassword.objects.filter(account=account)
        self.assertEqual(passwords.count(), 1)
        password = passwords[0]
        self.assertEqual(password.password,
                         encrypt_launchpad_password(DEFAULT_USER_PASSWORD,
                                                    salt=salt))

    def test_create_account_with_no_rationale(self):
        salt = generate_salt()
        account = Account.objects.create_account(
            displayname='displayname', email_address='email@host.local',
            password=DEFAULT_USER_PASSWORD, salt=salt)

        self.assertEqual(account.displayname, 'displayname')
        self.assertEqual(account.creation_rationale,
                         AccountCreationRationale.OWNER_CREATED_LAUNCHPAD)
        self.assertEqual(account.status, AccountStatus.ACTIVE)

        emails = EmailAddress.objects.filter(account=account)
        self.assertEqual(emails.count(), 1)
        email = emails[0]
        self.assertEqual(email.email, 'email@host.local')
        self.assertEqual(email.status, EmailStatus.PREFERRED)

        passwords = AccountPassword.objects.filter(account=account)
        self.assertEqual(passwords.count(), 1)
        password = passwords[0]
        self.assertEqual(password.password,
                         encrypt_launchpad_password(DEFAULT_USER_PASSWORD,
                                                    salt=salt))

    def test_create_account_with_email_validated(self):
        salt = generate_salt()
        account = Account.objects.create_account(
            displayname='displayname', email_address='email@host.local',
            password=DEFAULT_USER_PASSWORD, salt=salt, email_validated=False)

        self.assertEqual(account.displayname, 'displayname')
        self.assertEqual(account.creation_rationale,
                         AccountCreationRationale.OWNER_CREATED_LAUNCHPAD)
        self.assertEqual(account.status, AccountStatus.ACTIVE)

        emails = EmailAddress.objects.filter(account=account)
        self.assertEqual(emails.count(), 1)
        email = emails[0]
        self.assertEqual(email.email, 'email@host.local')
        self.assertEqual(email.status, EmailStatus.NEW)

        passwords = AccountPassword.objects.filter(account=account)
        self.assertEqual(passwords.count(), 1)
        password = passwords[0]
        self.assertEqual(password.password,
                         encrypt_launchpad_password(DEFAULT_USER_PASSWORD,
                                                    salt=salt))

    def test_active_by_openid_no_accounts(self):
        result = Account.objects.active_by_openid('123456')
        self.assertIsNone(result)

    def test_active_by_openid_no_match(self):
        account = self.factory.make_account()
        assert account.openid_identifier != '123456'
        result = Account.objects.active_by_openid('123456')
        self.assertIsNone(result)

    def test_active_by_openid(self):
        account = self.factory.make_account()
        openid = account.openid_identifier
        for status, name in AccountStatus._get_choices():
            account.status = status
            account.save()
            result = Account.objects.active_by_openid(openid)
            if status == AccountStatus.ACTIVE:
                assert account.is_active
                self.assertEqual(result, account)
            else:
                self.assertIsNone(result)

    def test_verified_list_only_verified_accounts(self):
        accounts = Account.objects.verified()
        for account in accounts:
            emails = account.emailaddress_set.all()
            self.assertTrue(any([email.is_verified for email in emails]))

    def test_verified_no_duplicates(self):
        accounts = Account.objects.verified()
        self.assertEqual(accounts.count(), accounts.distinct().count())


class AccountTestCase(SSOBaseTestCase):

    def prepare_perms(self, has_perm):
        account = self.factory.make_account()

        def mock_get_backends():
            return [MockBackend(has_perm)]

        get_backends = a.get_backends
        a.get_backends = mock_get_backends
        return account, get_backends

    def test_last_login_when_user_doesnt_exists(self):
        account = self.factory.make_account()
        self.assertTrue(account.last_login is not None)

    def test_last_login_when_user_exists(self):
        account = self.factory.make_account()
        User.objects.get_or_create(username=account.openid_identifier)

        self.assertTrue(account.last_login is not None)

    def test_set_last_login_when_user_does_not_exists(self):
        account = self.factory.make_account()

        # we use now() here because last_login maps to django's auth model
        # which uses localtime.
        account.last_login = datetime.now()

        self.assertTrue(account.last_login is not None)

    def test_set_last_login_when_readonly(self):
        readonly_manager = ReadOnlyManager()
        account = self.factory.make_account()
        account.last_login = last_login = datetime(2010, 01, 01)
        self.assertEqual(account.last_login, last_login)

        assert not settings.READ_ONLY_MODE
        readonly_manager.set_readonly()
        self.addCleanup(readonly_manager.clear_readonly)

        # we use now() here because last_login maps to django's auth model
        # which uses localtime.
        account.last_login = now = datetime.now()
        self.assertEqual(account.last_login, last_login)
        self.assertNotEqual(account.last_login, now)

    def test_set_last_login_when_no_preferredemail(self):
        account = self.factory.make_account()
        account.emailaddress_set.all().update(status=EmailStatus.NEW)
        # we use now() here because last_login maps to django's auth model
        # which uses localtime.
        account.last_login = datetime.now()
        # Changed from assertRaises, as using it to test for database
        # exceptions causes transaction to be aborted and all tests following
        # it will fail. (It's only the case if the test case inherits
        # django.test.TestCase)
        # Test is has actually created a User object
        expected_count = 1 if gargoyle.is_active('ALLOW_UNVERIFIED') else 0
        self.assertEqual(
            expected_count,
            User.objects.filter(username=account.openid_identifier).count()
        )

    def test_is_active(self):
        account = self.factory.make_account()

        self.assertTrue(account.is_active)

    def test_is_staff(self):
        account = self.factory.make_account()

        self.assertFalse(account.is_staff)

    def test_is_authenticated(self):
        account = self.factory.make_account()

        self.assertTrue(account.is_authenticated)

    def test_is_superuser(self):
        account = self.factory.make_account()

        self.assertFalse(account.is_superuser)

    def test_is_not_verified(self):
        account = self.factory.make_account(email_validated=False)
        self.assertFalse(account.is_verified)

    def test_is_verified(self):
        account = self.factory.make_account()
        self.assertTrue(account.is_verified)

    def test_first_name(self):
        account = self.factory.make_account(displayname='Sample Person')
        self.assertEqual(account.first_name, "Sample")

    def test_full_name(self):
        account = self.factory.make_account(displayname='Sample Person')
        self.assertEqual(account.get_full_name(), "Sample Person")

    def test_twofactor_attempts_default(self):
        account = self.factory.make_account()
        self.assertEqual(account.twofactor_attempts, 0)

    def test_has_module_perms_when_not_active(self):
        account = self.factory.make_account()
        account.status = AccountStatus.NOACCOUNT

        self.assertFalse(account.has_module_perms('app'))

    def test_has_module_perms_returning_true(self):
        account, get_backends = self.prepare_perms(True)
        try:
            self.assertTrue(account.has_module_perms('app'))
        finally:
            a.get_backends = get_backends

    def test_has_module_perms_returning_false(self):
        account, get_backends = self.prepare_perms(False)
        try:
            self.assertFalse(account.has_module_perms('app'))
        finally:
            a.get_backends = get_backends

    def test_has_perm_returning_true(self):
        account, get_backends = self.prepare_perms(True)
        try:
            self.assertTrue(account.has_perm('can_change_account'))
        finally:
            a.get_backends = get_backends

    def test_has_perm_returning_false(self):
        account, get_backends = self.prepare_perms(False)
        try:
            self.assertFalse(account.has_perm('can_change_account'))
        finally:
            a.get_backends = get_backends

    def test_has_perm_when_account_is_not_active(self):
        account = self.factory.make_account()
        account.status = AccountStatus.NOACCOUNT

        self.assertFalse(account.has_perm('can_change_account'))

    @switches(ALLOW_UNVERIFIED=True)
    def test_new_account_has_preferred_email_with_flag(self):
        account = self.factory.make_account(email_validated=False)
        self.assertIsNotNone(account.preferredemail)

    @switches(ALLOW_UNVERIFIED=False)
    def test_new_account_has_preferred_email_no_flag(self):
        account = self.factory.make_account(email_validated=False)
        self.assertIsNone(account.preferredemail)

    def test_new_account_has_preferred_email_with_selective_flag(self):
        email = self.factory.make_email_address()
        condition_set = ('identityprovider.gargoyle.AccountConditionSet('
                         'identityprovider.account)')
        self.conditionally_enable_flag('ALLOW_UNVERIFIED', 'email',
                                       email, condition_set)

        account = self.factory.make_account(email=email,
                                            email_validated=False)
        self.assertIsNotNone(account.preferredemail)

    def test_set_preferred_with_unverified_email(self):
        account = self.factory.make_account(email_validated=False)
        with self.assertRaises(ValidationError):
            account.preferredemail = account.emailaddress_set.get()

    def test_can_reset_password_without_verified_email(self):
        account = self.factory.make_account(email_validated=False)
        self.assertTrue(account.can_reset_password)

    def test_validated_email_address_is_preferred_email_by_default(self):
        account = self.factory.make_account(email_validated=False)
        email_address = account.emailaddress_set.create(
            email='foobar@canonical.com',
            status=EmailStatus.VALIDATED)
        self.assertEqual(account.preferredemail.email, 'foobar@canonical.com')

        email_address = EmailAddress.objects.get(pk=email_address.id)
        self.assertEqual(email_address.status, EmailStatus.PREFERRED)

    def test_verified_emails_has_preferred_first(self):
        account = self.factory.make_account()
        self.factory.make_email_for_account(account,
                                            status=EmailStatus.VALIDATED)
        emails = account.verified_emails()
        self.assertTrue(len(emails) > 1)
        self.assertEqual(emails[0].status, EmailStatus.PREFERRED)
        self.assertEqual(emails[1].status, EmailStatus.VALIDATED)

    def test_account_suspend_reset_password(self):
        account = self.factory.make_account(password=DEFAULT_USER_PASSWORD,
                                            status=AccountStatus.SUSPENDED)

        account_password = AccountPassword.objects.get(account=account)
        self.assertEqual(account_password.password, 'invalid')

    def test_save_when_readonly(self):
        readonly_manager = ReadOnlyManager()
        account = self.factory.make_account()
        assert account.status == AccountStatus.ACTIVE

        assert not settings.READ_ONLY_MODE
        readonly_manager.set_readonly()
        self.addCleanup(readonly_manager.clear_readonly)

        account.suspend()
        # refresh account from db
        account = Account.objects.get(id=account.id)
        self.assertEqual(account.status, AccountStatus.ACTIVE)

    def test_save_when_no_password(self):
        account = self.factory.make_account()
        # remove all passwords
        AccountPassword.objects.filter(account=account).delete()

        # reload account, to bypass django orm cache
        account = Account.objects.get(pk=account.pk)
        # trigger test
        account.status = AccountStatus.SUSPENDED
        account.save()

        self.assertEqual(
            AccountPassword.objects.filter(account=account).count(), 0)

    def test_sites_with_active_sessions_when_returns_empty_result(self):
        account = self.factory.make_account()
        sites_count = account.sites_with_active_sessions().count()
        self.assertEqual(sites_count, 0)

    def test_sites_with_active_sessions_when_one_site_is_active(self):
        account = self.factory.make_account()

        account.openidrpsummary_set.create(
            date_last_used=datetime.utcnow(),
            trust_root='http://trust-root.example.com',
            openid_identifier='openid-identifier')

        account.openidrpsummary_set.create(
            date_last_used=datetime.utcnow() - timedelta(days=3),
            trust_root='http://trust-root-2.example.com')

        sites_count = account.sites_with_active_sessions().count()
        self.assertEqual(sites_count, 1)

    @patch('identityprovider.models.account.datetime')
    def test_sites_with_active_sessions_use_utc(self, mock_datetime):
        mock_datetime.utcnow.return_value = datetime.utcnow()
        mock_datetime.side_effect = lambda *args, **kw: datetime(*args, **kw)

        account = self.factory.make_account()
        sites_count = account.sites_with_active_sessions().count()

        self.assertEqual(sites_count, 0)
        self.assertEqual(mock_datetime.utcnow.called, True)

    def test_warn_about_backup_device(self):
        account = self.factory.make_account()
        # use assertEqual instead to assertTrue to ensure attr is a boolean
        self.assertEqual(account.warn_about_backup_device, True)

    def test_need_backup_device_warning_no_devices(self):
        account = self.factory.make_account()
        assert account.warn_about_backup_device
        assert account.devices.count() == 0
        self.assertFalse(account.need_backup_device_warning)

    def test_need_backup_device_warning_one_device(self):
        account = self.factory.make_account()
        self.factory.make_device(account=account)

        assert account.warn_about_backup_device
        assert account.devices.count() == 1
        self.assertTrue(account.need_backup_device_warning)

    def test_need_backup_device_warning_one_device_warn_setting_false(self):
        account = self.factory.make_account()
        account.warn_about_backup_device = False
        account.save()
        self.factory.make_device(account=account)

        assert not account.warn_about_backup_device
        assert account.devices.count() == 1
        self.assertFalse(account.need_backup_device_warning)

    def test_need_backup_device_warning_two_devices(self):
        account = self.factory.make_account()
        self.factory.make_device(account=account)
        self.factory.make_device(account=account)

        assert account.warn_about_backup_device
        assert account.devices.count() == 2
        self.assertFalse(account.need_backup_device_warning)

    def test_suspend(self):
        account = self.factory.make_account()
        assert account.status != AccountStatus.SUSPENDED

        account.suspend()
        self.assertEqual(account.status, AccountStatus.SUSPENDED)

        # the status change was also saved in the DB
        account = Account.objects.get(id=account.id)
        self.assertEqual(account.status, AccountStatus.SUSPENDED)


class AccountPasswordTestCase(TestCase):

    def test_unicode(self):
        account = Account(openid_identifier='oid', displayname='displayname')
        password = AccountPassword(account=account, password='password')
        self.assertEqual(unicode(password), u'Password for displayname')


class CreateOAuthTokenForAccountTestCase(SSOBaseTestCase):

    def setUp(self):
        super(CreateOAuthTokenForAccountTestCase, self).setUp()
        self.account = self.factory.make_account(
            displayname='test', email='test-oauth@example.com',
            password=DEFAULT_USER_PASSWORD)
        self.user = User.objects.create_user(
            self.account.openid_identifier,
            'test@example.com', 'password')

    def test_when_account_has_associated_consumer(self):
        consumer, _ = Consumer.objects.get_or_create(user=self.user)

        token = self.account.create_oauth_token('new-token')

        self.assertEqual(token.consumer.id, consumer.id)

    def test_get_or_create(self):
        consumer, _ = Consumer.objects.get_or_create(user=self.user)

        token, created = self.account.get_or_create_oauth_token('new-token')

        self.assertTrue(created)
        self.assertEqual(token.consumer.id, consumer.id)

        token2, created = self.account.get_or_create_oauth_token('new-token')
        self.assertFalse(created)
        self.assertEqual(token2, token)
        self.assertNotEqual(token2.updated_at, token.updated_at)

        token3, created = self.account.get_or_create_oauth_token('new-token2')
        self.assertTrue(created)
        self.assertNotEqual(token, token3)
        self.assertEqual(token3.consumer.id, consumer.id)

    def test_get_or_create_when_multiple_results(self):
        consumer, _ = Consumer.objects.get_or_create(user=self.user)

        # create multiple tokens
        token1 = consumer.token_set.create(name='new-token')
        token2 = consumer.token_set.create(name='new-token')
        token2.created_at = token1.created_at + timedelta(seconds=10)
        token2.save()

        token, created = self.account.get_or_create_oauth_token('new-token')

        self.assertEqual(token, token2)
        self.assertFalse(created)

    def test_get_when_account_has_no_associated_consumer(self):
        Consumer.objects.filter(user=self.user).delete()

        token = self.account.create_oauth_token('new-token')

        self.assertEqual(token.consumer.user.id, self.user.id)

    def test_get_or_create_when_account_has_no_associated_consumer(self):
        Consumer.objects.filter(user=self.user).delete()

        token, created = self.account.get_or_create_oauth_token('new-token')

        self.assertTrue(created)
        self.assertEqual(token.consumer.user.id, self.user.id)

    def test_invalidate_oauth_tokens(self):
        token, created = self.account.get_or_create_oauth_token('new-token')
        assert self.account.oauth_tokens()

        self.account.invalidate_oauth_tokens()
        self.assertEqual(self.account.oauth_tokens().count(), 0)


class AuthenticateUserTestCase(SSOBaseTestCase):

    def setUp(self):
        super(AuthenticateUserTestCase, self).setUp()
        self.email = 'test@example.com'
        self.password = DEFAULT_USER_PASSWORD
        self.account = self.make_account()
        self.user = User.objects.create_user(
            self.account.openid_identifier,
            self.email, self.password)
        self.enable_flag()

    def enable_flag(self):
        switcher = switches(ALLOW_UNVERIFIED=True)
        switcher.patch()
        self.addCleanup(switcher.unpatch)

    def make_account(self):
        account = self.factory.make_account(email=self.email,
                                            password=self.password)
        return account

    def assert_failed_login(self, exception):
        with self.assertRaises(exception):
            authenticate_user(self.email, self.password)

    def test_account_suspended(self):
        self.account.status = AccountStatus.SUSPENDED
        self.account.save()
        self.assert_failed_login(AccountSuspended)

    def test_account_deactivated(self):
        self.account.status = AccountStatus.DEACTIVATED
        self.account.save()
        self.assert_failed_login(AccountDeactivated)

    def test_failed_login(self):
        self.password = 'wrong password'
        self.assert_failed_login(AuthenticationError)

    def test_new_email_not_allowed(self):
        email = self.account.emailaddress_set.get(email=self.email)
        email.status = EmailStatus.NEW
        email.save()
        with switches(ALLOW_UNVERIFIED=False, LOGIN_BY_PHONE=False):
            self.assert_failed_login(AuthenticationError)

    def test_new_email_allowed(self):
        email = self.account.emailaddress_set.get(email=self.email)
        email.status = EmailStatus.NEW
        email.save()

        result = authenticate_user(self.email, self.password)

        self.assertEqual(result, self.account)

    def test_authenticate_user(self):
        result = authenticate_user(self.email, self.password)
        self.assertEqual(result, self.account)

    def test_invalidated_email(self):
        email_obj = self.account.emailaddress_set.get(email=self.email)
        email_obj.invalidate()

        # this is not distinguishable if another user registered with
        # the same email from a password mismatch
        with self.assertRaises(AuthenticationError):
            authenticate_user(self.email, self.password)

    def test_allow_unverified_disabled_and_login_by_phone_enabled(self):
        email = self.account.emailaddress_set.get(email=self.email)
        email.status = EmailStatus.NEW
        email.save()

        # enable the LOGIN_BY_PHONE flag selective on team membership
        team_name = 'tomb-riders'
        key = 'LOGIN_BY_PHONE'
        field_name = 'team'
        value = team_name
        condition_set = ('identityprovider.gargoyle.LPTeamConditionSet('
                         'lp_team)')
        self.conditionally_enable_flag(key, field_name, value, condition_set)

        # without proper team, authenticate_user will not succeed
        with switches(ALLOW_UNVERIFIED=False):
            self.assert_failed_login(AuthenticationError)

        # bind account with the team
        team = self.factory.make_team(name=team_name)
        self.factory.add_account_to_team(self.account, team)

        with switches(ALLOW_UNVERIFIED=False):
            result = authenticate_user(self.email, self.password)
        self.assertEqual(result, self.account)


class AuthenticateUserSelectiveTestCase(TeamConditionSelectiveMixin,
                                        AuthenticateUserTestCase):
    key = 'ALLOW_UNVERIFIED'
