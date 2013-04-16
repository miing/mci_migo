from StringIO import StringIO

from django.core.management import call_command
from mock import patch

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

    def test_get_account_openid_for_valid_username(self):
        stdout = StringIO()
        stderr = StringIO()

        call_command('get_account_openid', username=self.person.name,
                     stdout=stdout, stderr=stderr)

        expected = self.account.openid_identifier
        self.assert_output_equal(stderr, '')
        self.assert_output_equal(stdout, expected)

    @patch('sys.exit')
    def test_get_account_openid_without_username(self, mock_sys_exit):
        stdout = StringIO()
        stderr = StringIO()

        call_command('get_account_openid', stdout=stdout, stderr=stderr)

        mock_sys_exit.called_once_with(1)
        expected = "Error: Need to specify a username."
        self.assert_output_contain(stderr, expected)
        self.assert_output_equal(stdout, '')

    @patch('sys.exit')
    def test_get_account_openid_for_valid_username_without_account(
            self, mock_sys_exit):
        stdout = StringIO()
        stderr = StringIO()
        self.account.delete()
        person = Person.objects.get(pk=self.person.pk)
        assert person.account is None

        call_command('get_account_openid', username=person.name,
                     stdout=stdout, stderr=stderr)

        mock_sys_exit.called_once_with(1)
        expected = ("Error: LP account matching username '%s' is not linked "
                    "to any SSO account." % person.name)
        self.assert_output_contain(stderr, expected)
        self.assert_output_equal(stdout, '')

    @patch('sys.exit')
    def test_get_account_openid_for_invalid_username(self, mock_sys_exit):
        stdout = StringIO()
        stderr = StringIO()

        call_command('get_account_openid', username='invalid',
                     stdout=stdout, stderr=stderr)

        mock_sys_exit.called_once_with(1)
        expected = "Error: No LP account found matching username 'invalid'."
        self.assert_output_contain(stderr, expected)
        self.assert_output_equal(stdout, '')
