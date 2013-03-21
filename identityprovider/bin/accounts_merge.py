#!/usr/bin/env python
import os
import sys

from cStringIO import StringIO
from optparse import OptionParser
from django.test import TestCase

from identityprovider.models.const import TokenType


ERROR = """E03: Source account was used to log in to other services.  Merging
accounts will make it so the user could no longer access those other
services using the old SSO account.  The user may lose access to
history or important information.  Please confirm this with the user
before continuing.

The other services are:

%s

Use --skip-safety-warnings to merge the accounts anyway."""


class AccountMerger(object):

    def __init__(self, dry_run, skip_safety_warnings):
        self.dry_run = dry_run
        self.skip_safety_warnings = skip_safety_warnings

    def merge(self, destination_id, source_id):
        source = self.get_account(source_id)
        if source is None:
            self.error("E01: Source account was not found", 2)

        destination = self.get_account(destination_id)
        if destination is None:
            self.error("E02: Destination account was not found", 2)

        used_to_log_in = self.account_was_used_to_log_in(source)
        if used_to_log_in and not self.skip_safety_warnings:
            sites = source.last_authenticated_sites(limit=None)
            urls = [s.trust_root for s in sites]
            self.error(ERROR % '\n'.join(urls))

        if source.pk == destination.pk:
            self.error("E08: Trying to merge account with itself")

        if destination.preferredemail is None:
            self.error("E04: Destination account doesn't have preferred "
                       "email. Looks like it isn't fully activated.")

        if source.preferredemail is None:
            self.error("E05: Source account doesn't have preferred email. "
                       "Looks like it isn't fully activated.")

        if source.person and source.person.is_team():
            self.error("E06: Can't merge accounts connected to teams.")

        if destination.person and destination.person.is_team():
            self.error("E07: Can't merge accounts connected to teams.")

        self.merge_email_addresses(destination, source)
        self.merge_accounts(destination, source)

        if not self.dry_run:
            destination.save()
            source.save()

    def merge_email_addresses(self, destination, source):
        from identityprovider.models.const import EmailStatus
        emails = list(source.emailaddress_set.all())
        if not self.dry_run:
            for email in emails:
                # Remove PREFERRED status from email on the source account and
                # add all email addresses from source to destination
                if email.status == EmailStatus.PREFERRED:
                    email.status = EmailStatus.VALIDATED
                destination.emailaddress_set.add(email)

    def merge_accounts(self, destination, source):
        from identityprovider.models.const import AccountStatus
        from oauth_backend.models import Consumer
        source.status = AccountStatus.DEACTIVATED
        source.authtoken_set.all().delete()
        source.status_comment = (
            "Merged with account id:%d (openid:%s)" % (
            destination.pk, destination.openid_identifier) + "\n" +
            str(source.status_comment))
        try:
            for t in source.oauth_tokens():
                t.delete()
        except Consumer.DoesNotExist:
            pass

    def account_was_used_to_log_in(self, account):
        return len(account.last_authenticated_sites()) > 0

    def error(self, message, error_code=1):
        sys.stderr.write("%s\n" % message)
        sys.exit(error_code)

    def get_account(self, openid_or_email):
        from identityprovider.models.account import Account
        try:
            return Account.objects.get(openid_identifier=openid_or_email)
        except Account.DoesNotExist:
            return Account.objects.get_by_email(openid_or_email)


class AccountMergerTestCase(TestCase):

    def setUp(self):
        self.merger = AccountMerger(False, False)
        sys.stderr = StringIO()

    def tearDown(self):
        from identityprovider.models.account import Account
        account = Account.objects.get_by_email("merger@example.com")
        if account:
            account.delete()
        Account.objects.filter(displayname="s").delete()
        Account.objects.filter(displayname="d").delete()
        from identityprovider.models.person import Person
        Person.objects.filter(name__startswith="merger").delete()

    def create_account(self, **kwargs):
        from identityprovider.models.account import Account
        params = {
            'displayname': "merger",
            'email_address': "merger@example.com",
            'password': "merger"
        }
        params.update(kwargs)
        return Account.objects.create_account(**params)

    def test_get_account_using_openid(self):
        account_1 = self.create_account()
        account_2 = self.merger.get_account(account_1.openid_identifier)
        self.assertEqual(account_1.pk, account_2.pk)

    def test_get_account_using_email(self):
        account_1 = self.create_account()
        account_2 = self.merger.get_account("merger@example.com")
        self.assertEqual(account_1.pk, account_2.pk)

    def test_get_account_returns_none(self):
        self.assertTrue(self.merger.get_account("a") is None)

    def test_account_was_used_to_log_in_returns_false(self):
        account = self.create_account()
        self.assertFalse(self.merger.account_was_used_to_log_in(account))

    def test_account_was_used_to_log_in_returns_true(self):
        account = self.create_account()
        account.openidrpsummary_set.create(
            openid_identifier=account.openid_identifier,
            trust_root="http://localhost/")
        self.assertTrue(self.merger.account_was_used_to_log_in(account))

    def create_account_pair(self):
        s = self.create_account(displayname="s", email_address="s@example.com")
        d = self.create_account(displayname="d", email_address="d@example.com")
        return s, d

    def test_merge_accounts_without_oauth_tokens(self):
        s, d = self.create_account_pair()

        s.authtoken_set.create(token_type=TokenType.NEWACCOUNT, token="d")

        self.merger.merge_accounts(d, s)

        from identityprovider.models.const import AccountStatus
        self.assertEqual(s.status, AccountStatus.DEACTIVATED)
        self.assertEqual(s.authtoken_set.count(), 0)

    def test_merge_accounts_with_oauth_tokens(self):
        s, d = self.create_account_pair()
        s.create_oauth_token("test")
        self.merger.merge_accounts(d, s)
        self.assertEqual(s.oauth_consumer.token_set.count(), 0)

    def test_merger_email_addresses(self):
        s, d = self.create_account_pair()
        self.merger.merge_email_addresses(d, s)

        self.assertEqual(s.emailaddress_set.count(), 0)
        emails = list(sorted(e.email for e in d.emailaddress_set.all()))
        self.assertEqual(emails, ["d@example.com", "s@example.com"])
        self.assertEqual(d.preferredemail.email, "d@example.com")

    def create_person(self, account, name):
        from identityprovider.models.person import Person
        from identityprovider.models.account import LPOpenIdIdentifier

        lp_openid = LPOpenIdIdentifier.objects.create(
            openid_identifier=account.openid_identifier)
        person = Person.objects.create(
            displayname=account.displayname,
            lp_account=lp_openid.lp_account,
            name=name)

        return person

    def test_merge_with_sucessfull_merge(self):
        s, d = self.create_account_pair()
        self.merger.merge(d.openid_identifier, s.openid_identifier)
        from identityprovider.models.const import AccountStatus
        from identityprovider.models.account import Account
        # Refresh account from db
        s = Account.objects.get(openid_identifier=s.openid_identifier)
        self.assertEqual(s.status, AccountStatus.DEACTIVATED)

    def assertErrorCode(self, code, method, *args, **kwargs):
        try:
            method(*args, **kwargs)
            self.fail()
        except SystemExit:
            message = sys.stderr.getvalue()
            self.assertTrue(message.startswith(code))

    def test_merge_fails_bad_source_account(self):
        self.create_account()
        self.assertErrorCode("E02", self.merger.merge,
                             "two", "merger@example.com")

    def test_merge_fails_bad_destination_account(self):
        self.assertErrorCode("E01", self.merger.merge, None, "one")

    def test_merge_fails_source_account_was_used_to_log_in(self):
        s, d = self.create_account_pair()
        s.openidrpsummary_set.create(
            openid_identifier=s.openid_identifier,
            trust_root="http://localhost/")
        self.assertErrorCode("E03", self.merger.merge,
                             "d@example.com", "s@example.com")

    def test_merge_fails_destination_account_does_not_have_eamil(self):
        s, d = self.create_account_pair()
        d.emailaddress_set.all().delete()
        self.assertErrorCode("E04", self.merger.merge,
                             d.openid_identifier, "s@example.com")

    def test_merge_fails_source_account_does_not_have_eamil(self):
        s, d = self.create_account_pair()
        s.emailaddress_set.all().delete()
        self.assertErrorCode("E05", self.merger.merge,
                             d.openid_identifier, s.openid_identifier)

    def change_person_into_team(self, person):
        person.teamowner = person
        person.save()

    def test_merge_fails_source_person_is_team(self):
        s, d = self.create_account_pair()
        self.change_person_into_team(self.create_person(s, "merger_s"))
        self.assertErrorCode("E06", self.merger.merge,
                             d.openid_identifier, s.openid_identifier)

    def test_merge_fails_destination_person_is_team(self):
        s, d = self.create_account_pair()
        self.change_person_into_team(self.create_person(d, "merger_d"))
        self.assertErrorCode("E07", self.merger.merge,
                             d.openid_identifier, s.openid_identifier)

    def test_merge_fails_if_you_try_to_merge_account_to_itself(self):
        s = self.create_account(displayname="s", email_address="s@example.com")
        self.assertErrorCode("E08", self.merger.merge,
                             s.openid_identifier, s.openid_identifier)


def main():
    parser = OptionParser()
    parser.add_option("--django-settings", default="settings",
                      help="Django settings module.")
    parser.add_option("--destination",
                      help="A destination account open id or email.")
    parser.add_option("--source",
                      help="An account which will be merged with destination.")
    parser.add_option("--dry-run", default=False, action="store_true",
                      help="Dry run, don't actually perform the merge.")
    parser.add_option("--skip-safety-warnings", default=False,
                      action="store_true",
                      help="Go ahead with account merging, despite warnings.")
    parser.add_option("--test", action="store_true", default=False,
                      help="Run tests.")

    (options, args) = parser.parse_args()

    os.environ['DJANGO_SETTINGS_MODULE'] = options.django_settings
    sys.path.append(".")

    if options.test:
        from unittest import main
        main(argv=["AccountMergerTestCase"])
    else:
        if options.source is None or options.destination is None:
            parser.print_help()
        else:
            if options.dry_run:
                print "Dry run, no changes will be saved to DB."
            account_merger = AccountMerger(options.dry_run,
                                           options.skip_safety_warnings)
            account_merger.merge(options.destination, options.source)
            print "%s merged into %s" % (options.source, options.destination)


if __name__ == '__main__':
    main()
