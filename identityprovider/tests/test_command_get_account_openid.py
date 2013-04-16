import operator
from StringIO import StringIO

from django.core.management import call_command
from mock import patch

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
        self.assertEqual(output, expected)

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

    @patch('sys.exit')
    def test_get_account_openid_without_username(self, mock_sys_exit):
        stdout = StringIO()
        stderr = StringIO()

        call_command('get_account_openid', stdout=stdout, stderr=stderr)

        mock_sys_exit.assert_called_once_with(1)
        expected = "Error: Enter at least one label."
        self.assert_output_contain(stderr, expected)
        self.assert_output_equal(stdout, '')

    @patch('sys.exit')
    def test_get_account_openid_multiple_usernames(self, mock_sys_exit):
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

    @patch('sys.exit')
    def test_get_account_openid_for_valid_username_without_account(
            self, mock_sys_exit):
        stdout = StringIO()
        stderr = StringIO()
        self.account.delete()
        person = Person.objects.get(pk=self.person.pk)
        assert person.account is None

        call_command('get_account_openid', person.name,
                     stdout=stdout, stderr=stderr)

        mock_sys_exit.assert_called_once_with(1)
        expected = ("Error: LP account matching username '%s' is not linked "
                    "to any SSO account." % person.name)
        self.assert_output_contain(stderr, expected)
        self.assert_output_equal(stdout, '')

    @patch('sys.exit')
    def test_get_account_openid_for_invalid_username(self, mock_sys_exit):
        stdout = StringIO()
        stderr = StringIO()

        call_command('get_account_openid', 'invalid',
                     stdout=stdout, stderr=stderr)

        mock_sys_exit.assert_called_once_with(1)
        expected = "Error: No LP account found matching username 'invalid'."
        self.assert_output_contain(stderr, expected)
        self.assert_output_equal(stdout, '')
