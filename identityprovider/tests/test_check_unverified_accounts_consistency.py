from datetime import datetime, timedelta
from StringIO import StringIO

from django.core.management import call_command, CommandError

from identityprovider.models import Account
from identityprovider.models.const import AccountStatus
from identityprovider.tests.utils import (
    SSOBaseTestCase,
    patch_settings,
)


class CheckUnverifiedAccountsTestCase(SSOBaseTestCase):

    command_name = 'check_unverified_accounts_consistency'
    delete_threshold = 5

    def setUp(self):
        super(CheckUnverifiedAccountsTestCase, self).setUp()

        self.stderr = StringIO()
        self.call_command = lambda: call_command(self.command_name,
                                                 stderr=self.stderr)

        self.mock_logger = self._apply_patch(
            'identityprovider.management.commands.'
            'check_unverified_accounts_consistency.logging')
        self.mock_now = self._apply_patch(
            'identityprovider.management.commands.'
            'check_unverified_accounts_consistency.datetime')
        self.mock_now.utcnow.return_value = self.now = datetime.utcnow()

        self.sys_exit = self._apply_patch('sys.exit')

        p = patch_settings(
            DELETE_UNVERIFIED_ACCOUNT_AFTER_DAYS=self.delete_threshold)
        p.start()
        self.addCleanup(p.stop)

    def create_unverified_account(self, seconds_old):
        truncated = self.now.replace(hour=0, minute=0, second=0, microsecond=0)
        created = truncated - timedelta(seconds=seconds_old)
        account = self.factory.make_account(
            status=AccountStatus.SUSPENDED,
            email_validated=False, date_created=created)

        assert account.status == AccountStatus.SUSPENDED
        assert account.date_created == created
        assert not account.verified_emails().exists()

        return account

    def assert_all_good(self):
        self.mock_logger.info.assert_called_one_with(
            'check_unverified_accounts_consistency: no accounts found in '
            'inconsistent state.')
        self.assertFalse(self.sys_exit.called)
        self.assertFalse(self.mock_logger.warning.called)
        self.assertFalse(self.mock_logger.error.called)
        self.assertFalse(self.mock_logger.exception.called)
        self.stderr.seek(0)
        self.assertEqual(self.stderr.read(), '')

    def test_no_accounts(self):
        assert not Account.objects.exists()

        self.call_command()

        self.assert_all_good()

    def test_only_valid_accounts(self):
        seconds = self.delete_threshold * 3600
        self.create_unverified_account(seconds_old=seconds)
        self.create_unverified_account(seconds_old=seconds - 1)

        self.call_command()

        self.assert_all_good()

    def test_some_invalid_accounts(self):
        seconds = self.delete_threshold * 3600 * 24
        self.create_unverified_account(seconds_old=seconds * 2)
        self.create_unverified_account(seconds_old=seconds + 1)
        self.create_unverified_account(seconds_old=seconds)
        self.create_unverified_account(seconds_old=seconds - 1)

        with self.assertRaises(CommandError) as cm:
            self.call_command()

        msg = ('found %s suspended and unverified accounts older than %s '
               'days (those should be deleted).')
        self.mock_logger.warning.assert_called_once_with(
            'check_unverified_accounts_consistency: ' + msg,
            2, self.delete_threshold)
        self.assertEqual(msg % (2, self.delete_threshold),
                         str(cm.exception))
        self.assertFalse(self.mock_logger.info.called)
        self.assertFalse(self.mock_logger.error.called)
        self.assertFalse(self.mock_logger.exception.called)
