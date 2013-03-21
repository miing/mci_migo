from datetime import datetime, timedelta

from django.core.management import call_command
from gargoyle.testutils import switches
from mock import patch, call

from identityprovider.models import Account
from identityprovider.models.const import AccountStatus
from identityprovider.tests.utils import (
    SSOBaseTestCase,
    patch_settings,
)


class SuspendUnverifiedAccountsTestCase(SSOBaseTestCase):

    action_after_days = 5
    warn_before_days = 1

    account_action = 'suspend'
    account_status = AccountStatus.ACTIVE
    action = 'suspension'
    command_name = 'suspend_unverified_accounts'
    new_settings = (
        'SUSPEND_UNVERIFIED_ACCOUNT_AFTER_DAYS',
        'WARN_SUSPEND_UNVERIFIED_ACCOUNT_BEFORE_DAYS',
    )

    def setUp(self):
        super(SuspendUnverifiedAccountsTestCase, self).setUp()

        self.call_command = lambda: call_command(self.command_name)

        self.mock_send_warning = self._apply_patch(
            'identityprovider.emailutils.send_action_required_warning')
        self.mock_send_notice = self._apply_patch(
            'identityprovider.emailutils.send_action_applied_notice')
        self.mock_logger = self._apply_patch(
            'identityprovider.management.commands.suspend_unverified_accounts.'
            'logging')
        self.mock_now = self._apply_patch(
            'identityprovider.management.commands.suspend_unverified_accounts.'
            'datetime')
        self.mock_now.utcnow.return_value = self.now = datetime.utcnow()

        # enable ALLOW_UNVERIFIED
        p = switches(ALLOW_UNVERIFIED=True)
        p.patch()
        self.addCleanup(p.unpatch)

        new_settings = zip(self.new_settings,
                           (self.action_after_days, self.warn_before_days))
        p = patch_settings(**dict(new_settings))
        p.start()
        self.addCleanup(p.stop)

    def create_unverified_account(self, days_old, invalidated_email=False):
        created = self.now - timedelta(days=days_old)
        # build known emails for future asserts are easier, specially when the
        # account is deleted
        email = '%s@example.com' % days_old
        name = 'User %s days old' % days_old
        account = self.factory.make_account(
            status=self.account_status, email=email, displayname=name,
            email_validated=False, date_created=created)

        assert account.status == self.account_status
        assert account.date_created == created
        assert not account.verified_emails().exists()

        if invalidated_email:
            email = account.emailaddress_set.get()
            email.invalidate()

        return account

    def create_accounts(self):
        # define interval so creation date varies for all interesting values
        start = self.action_after_days - self.warn_before_days - 1  # 3
        end = self.action_after_days + 2  # 7
        accounts = {}
        for age in xrange(start, end):
            accounts[age] = self.create_unverified_account(days_old=age)

        return accounts

    def assert_info_logging(self, warn_account, changed_account):
        log_calls = [
            call('Notified %r about future account %s.',
                 warn_account, self.action),
            call('Account %s for %s succeeded.', self.action, changed_account),
        ]
        self.mock_logger.info.assert_has_calls(log_calls)

    def assert_warning_logging(self, account):
        self.mock_logger.warning.assert_called_once_with(
            'Can not notify %r about %s since no preferredemail is set.',
            account, self.action,
        )

    def assert_accounts_changed(self, accounts):
        # every account but 5 should have not been modified
        for age, account in accounts.iteritems():
            reloaded = Account.objects.get(id=account.id)
            if age == 5:
                self.assertEqual(reloaded.status, AccountStatus.SUSPENDED)
            else:
                self.assertEqual(reloaded, account)

    def assert_happy_path(self, accounts):
        # account created 4 days ago has to be warned about future suspension
        self.mock_send_warning.assert_called_once_with(
            accounts[4], self.warn_before_days, self.account_action)
        # account created 5 days ago has to be notified of suspension
        self.mock_send_notice.assert_called_once_with(
            '5@example.com', 'User 5 days old',
            self.warn_before_days, self.account_action)
        self.assert_accounts_changed(accounts)

    def test_no_accounts(self):
        assert not Account.objects.exists()

        self.call_command()

        self.assertFalse(self.mock_send_warning.called)
        self.assertFalse(self.mock_send_notice.called)
        self.assertFalse(self.mock_logger.info.called)
        self.assertFalse(self.mock_logger.warning.called)
        self.assertFalse(self.mock_logger.exception.called)

    def test_command_happy_path(self):
        accounts = self.create_accounts()

        self.call_command()

        self.assert_happy_path(accounts)

    def test_info_logging_accounts(self):
        accounts = self.create_accounts()

        self.call_command()

        self.assert_info_logging(accounts[4], accounts[5])
        self.assertFalse(self.mock_logger.warning.called)
        self.assertFalse(self.mock_logger.exception.called)

    def test_account_4_no_preferred_email(self):
        accounts = self.create_accounts()
        accounts[4].emailaddress_set.all().delete()
        assert accounts[4].preferredemail is None

        self.call_command()

        self.assertFalse(self.mock_send_warning.called)
        self.mock_send_notice.assert_called_once_with(
            '5@example.com', 'User 5 days old',
            self.warn_before_days, self.account_action)

        self.mock_logger.info.assert_called_once_with(
            'Account %s for %s succeeded.', self.action, accounts[5])
        self.assert_warning_logging(accounts[4])
        self.assertFalse(self.mock_logger.exception.called)

    def test_account_5_no_preferred_email(self):
        accounts = self.create_accounts()
        accounts[5].emailaddress_set.all().delete()
        assert accounts[5].preferredemail is None

        self.call_command()

        self.mock_send_warning.assert_called_once_with(
            accounts[4], self.warn_before_days, self.account_action)
        self.assertFalse(self.mock_send_notice.called)

        self.assert_info_logging(accounts[4], accounts[5])
        self.assert_warning_logging(accounts[5])
        self.assertFalse(self.mock_logger.exception.called)

        # even if we fail to send the notification, the account was suspended
        self.assert_accounts_changed(accounts)

    def test_send_warning_exception_is_handled(self):
        accounts = self.create_accounts()

        self.mock_send_warning.side_effect = Exception()

        self.call_command()

        self.assert_happy_path(accounts)
        self.mock_logger.exception.assert_called_once_with(
            'Error while notifying %s for %r:', self.action, accounts[4],
        )

    def test_send_notice_exception_is_handled(self):
        accounts = self.create_accounts()

        self.mock_send_notice.side_effect = Exception()

        self.call_command()

        self.assert_happy_path(accounts)
        self.mock_logger.exception.assert_called_once_with(
            'Error while notifying %s to %r:', self.action, accounts[5],
        )

    def test_account_action_exception_is_handled(self):
        accounts = self.create_accounts()

        to_patch = 'identityprovider.models.Account.%s' % self.account_action
        with patch(to_patch) as p:
            p.side_effect = Exception()
            self.call_command()

        self.mock_send_warning.assert_called_once_with(
            accounts[4], self.warn_before_days, self.account_action)
        self.assertFalse(self.mock_send_notice.called)

        # every account should have not been modified
        for account in accounts.itervalues():
            self.assertEqual(account, Account.objects.get(id=account.id))
        self.mock_logger.exception.assert_called_once_with(
            'Error while applying %s to %r:', self.action, accounts[5],
        )

    def test_invalidated_emails_not_warned(self):
        account = self.create_unverified_account(
            days_old=self.warn_before_days + 3,
            invalidated_email=True,
        )

        self.call_command()

        self.assertFalse(self.mock_send_warning.called)
        self.assert_warning_logging(account)

    def test_invalidated_emails_action_applied(self):
        days_old = self.action_after_days
        account = self.create_unverified_account(
            days_old=days_old, invalidated_email=True,
        )

        self.call_command()

        self.assertFalse(self.mock_send_notice.called)
        self.assert_warning_logging(account)
        self.assert_accounts_changed({days_old: account})


class DeleteSuspendedAccountsTestCase(SuspendUnverifiedAccountsTestCase):

    account_action = 'delete'
    account_status = AccountStatus.SUSPENDED
    action = 'deletion'
    command_name = 'delete_suspended_accounts'
    new_settings = (
        'DELETE_UNVERIFIED_ACCOUNT_AFTER_DAYS',
        'WARN_DELETE_UNVERIFIED_ACCOUNT_BEFORE_DAYS',
    )

    def assert_accounts_changed(self, accounts):
        # every account but 5 should have not been modified
        for age, account in accounts.iteritems():
            if age == 5:
                with self.assertRaises(Account.DoesNotExist):
                    Account.objects.get(id=account.id)
            else:
                reloaded = Account.objects.get(id=account.id)
                self.assertEqual(reloaded, account)
