import operator
from StringIO import StringIO

from django.core.management import call_command, CommandError

from identityprovider.management.commands.get_account_openid import (
    Command as GetAccountOpenIdCommand,
)
from identityprovider.models import Person
from identityprovider.tests.helpers import SSOBaseTestCase


class GetAccountOpenIDCommandTestCase(SSOBaseTestCase):

    def setUp(self):
        super(GetAccountOpenIDCommandTestCase, self).setUp()

        self.account = self.factory.make_account()
        self.person = self.factory.make_person(account=self.account)

    def assert_output_equal(self, stream, expected):
        stream.seek(0)
        output = stream.read()
        self.assertEqual(output.strip(), expected.strip())

    def assert_output_contain(self, stream, expected):
        stream.seek(0)
        output = stream.read()
        self.assertIn(expected, output)

    def test_get_account_openid_return_username(self):
        username = self.person.name
        command = GetAccountOpenIdCommand()

        output = command.handle(username)

        self.assertEqual(output, "%s,%s" % (username,
                                            self.account.openid_identifier))

    def test_get_account_openid_for_valid_username(self):
        stdout = StringIO()
        stderr = StringIO()

        call_command('get_account_openid', self.person.name,
                     stdout=stdout, stderr=stderr)

        expected = "%s,%s" % (self.person.name, self.account.openid_identifier)
        self.assert_output_equal(stderr, '')
        self.assert_output_equal(stdout, expected)

    def test_get_account_openid_without_username(self):
        with self.assertRaises(CommandError) as cm:
            call_command('get_account_openid')

        expected = "Enter at least one label."
        self.assertEqual(expected, str(cm.exception))

    def test_get_account_openid_multiple_usernames(self):
        stdout = StringIO()
        stderr = StringIO()

        expected = []
        for i in range(3):
            account = self.factory.make_account()
            person = self.factory.make_person(account=account)
            expected.append((person.name, account.openid_identifier))

        usernames = map(operator.itemgetter(0), expected)
        call_command('get_account_openid', *usernames,
                     stdout=stdout, stderr=stderr)

        self.assert_output_equal(stderr, '')
        self.assert_output_equal(
            stdout, '\n'.join(("%s,%s" % item for item in expected)))

    def test_get_account_openid_for_valid_username_without_account(self):
        self.account.delete()
        person = Person.objects.get(pk=self.person.pk)
        assert person.account is None

        with self.assertRaises(CommandError) as cm:
            call_command('get_account_openid', person.name)

        expected = ("LP account matching username '%s' is not linked "
                    "to any SSO account." % person.name)
        self.assertEqual(expected, str(cm.exception))

    def test_get_account_openid_for_invalid_username(self):
        with self.assertRaises(CommandError) as cm:
            call_command('get_account_openid', 'invalid')

        expected = "No LP account found matching username 'invalid'."
        self.assertEqual(expected, str(cm.exception))
