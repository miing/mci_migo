import sys
import openid.store.nonce

from datetime import date, datetime, timedelta
from time import time
from StringIO import StringIO
from mock import Mock, patch

from django.contrib.sessions.models import Session
from django.core.management import call_command
from django.test import TestCase

from identityprovider.models import (
    Account,
    AccountPassword,
    EmailAddress,
    OpenIDNonce,
    OpenIDAssociation,
)
from identityprovider.tests.utils import (
    SSOBaseTestCaseMixin,
    skipOnSqlite,
)


@skipOnSqlite
class CleanupCommandTestCase(TestCase, SSOBaseTestCaseMixin):
    def setUp(self):
        Session.objects.all().delete()
        OpenIDNonce.objects.all().delete()
        OpenIDAssociation.objects.all().delete()

        self.addCleanup(Session.objects.all().delete)
        self.addCleanup(OpenIDNonce.objects.all().delete)
        self.addCleanup(OpenIDAssociation.objects.all().delete)

    def populate(self):
        call_command('populate', accounts=0, sessions=500,
                     nonces=500, associations=500, verbosity=0)

        self.assertEqual(500, Session.objects.count())
        self.assertEqual(500, OpenIDNonce.objects.count())
        self.assertEqual(500, OpenIDAssociation.objects.count())

    def make_test_accounts(self, count=0, date_created=None):
        for i in xrange(count):
            email = self.factory.make_email_address(prefix='isdtest+',
                                                    domain='canonical.com')

            account = self.factory.make_account(email=email)
            if date_created is not None:
                account.date_created = date_created
                account.save()
                EmailAddress.objects.filter(email=email).update(
                    date_created=date_created)

    def test_cleanup(self):
        self.populate()

        mock_stdout = StringIO()
        with patch.object(sys, 'stdout', mock_stdout):
            call_command('cleanup', verbosity=0)
        mock_stdout.seek(0)
        self.assertTrue('No items selected to clean up.' in mock_stdout.read())

    def test_cleanup_all(self):
        self.populate()
        call_command('cleanup', sessions=True, nonces=True, verbosity=0)

        self.assertEqual(0, Session.objects.filter(
            expire_date__lt=datetime.utcnow()).count())
        self.assertEqual(0, OpenIDNonce.objects.filter(timestamp__lt=(
            int(time()) - openid.store.nonce.SKEW)).count())

    def test_cleanup_sessions(self):
        self.populate()
        call_command('cleanup', sessions=True, verbosity=0)

        self.assertEqual(0, Session.objects.filter(
            expire_date__lt=datetime.utcnow()).count())
        self.assertEqual(500, OpenIDNonce.objects.count())

    def test_cleanup_nonces(self):
        self.populate()
        call_command('cleanup', nonces=True, verbosity=0)

        self.assertEqual(500, Session.objects.count())
        self.assertEqual(0, OpenIDNonce.objects.filter(timestamp__lt=(
            int(time()) - openid.store.nonce.SKEW)).count())

    def assert_testdata(self, accounts=0, emails=0, passwords=0):
        tomorrow = date.today() + timedelta(days=1)
        test_emails = EmailAddress.objects.filter(
            email__iregex=r'^isdtest\+[^@]+@canonical\.com$',
            date_created__lt=tomorrow)
        test_accounts = Account.objects.filter(
            displayname__startswith='Test Account')
        test_accountpasswords = AccountPassword.objects.filter(
            account__in=test_accounts)
        self.assertEqual(test_emails.count(), emails)
        self.assertEqual(test_accounts.count(), accounts)
        self.assertEqual(test_accountpasswords.count(), passwords)

    def test_cleanup_testdata_by_date(self):
        today = date.today()
        yesterday = today - timedelta(days=1)
        self.make_test_accounts(count=10, date_created=yesterday)
        self.make_test_accounts(count=5)
        self.assert_testdata(emails=15, accounts=15, passwords=15)

        call_command('cleanup', testdata=True,
                     date_created=today.strftime('%Y-%m-%d'),
                     verbosity=0)

        self.assert_testdata(emails=5, accounts=5, passwords=5)

    def test_cleanup_testdata_limit(self):
        self.make_test_accounts(count=10)

        name = ('identityprovider.management.commands.cleanup.Account.'
                'objects.filter')

        with patch(name) as mock_filter:
            mock_filter.return_value.__nonzero__.side_effect = [True, True,
                                                                False]
            call_command('cleanup', testdata=True, limit=5)

        self.assertEqual(mock_filter.return_value.delete.call_count, 2)

    def test_cleanup_testdata(self):
        self.make_test_accounts(count=10)
        self.assert_testdata(emails=10, accounts=10, passwords=10)

        call_command('cleanup', testdata=True, verbosity=0)

        self.assert_testdata(emails=0, accounts=0, passwords=0)

    def test_clean_testdata_verbose_progress(self):
        self.make_test_accounts(count=20)
        mock_stdout = Mock()

        call_command('cleanup', testdata=True, limit=5, verbosity=2,
                     stdout=mock_stdout)

        # 2 stdout writes per batch + 1 write for all accounts
        self.assertEqual(mock_stdout.write.call_count, 9)

    def test_clean_testdata_silent_progress(self):
        self.make_test_accounts(count=10)
        mock_stdout = Mock()

        call_command('cleanup', testdata=True, limit=5, verbosity=1,
                     stdout=mock_stdout)

        # 1 stdout write for all accounts
        self.assertEqual(mock_stdout.write.call_count, 1)

    def test_cleanup_orphaned_accounts(self):
        self.make_test_accounts(count=10)
        email_ids = EmailAddress.objects.filter(
            email__iregex=r'^isdtest\+[^@]+@canonical\.com$').values_list(
                'pk')[:5]
        EmailAddress.objects.filter(pk__in=email_ids).delete()

        call_command('cleanup', testdata=True)

        self.assert_testdata(emails=0, accounts=5, passwords=5)
