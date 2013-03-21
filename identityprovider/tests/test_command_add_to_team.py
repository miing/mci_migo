from StringIO import StringIO

from django.core.management import call_command
from django.test import TestCase

from mock import patch

from identityprovider.models import Account, Person
from identityprovider.tests import DEFAULT_USER_PASSWORD
from identityprovider.utils import get_object_or_none


class AddToTeamCommandTestCase(TestCase):

    def setUp(self):
        super(AddToTeamCommandTestCase, self).setUp()
        self.account = Account.objects.create_account(
            'test', 'test@canonical.com', DEFAULT_USER_PASSWORD,
            openid_identifier='openid')
        self.team = Person.objects.create(name='TeamA')

    def test_add_by_email(self):
        call_command('add_to_team', 'TeamA', email='test@canonical.com')
        self.assertTrue(self.account.person_in_team('TeamA'))

    def test_add_by_openid(self):
        call_command('add_to_team', 'TeamA', openid='openid')
        self.assertTrue(self.account.person_in_team('TeamA'))

    def test_add_to_nonexisting_team(self):
        call_command('add_to_team', 'TeamB', email='test@canonical.com')
        team = get_object_or_none(Person, name='TeamB')
        self.assertIsNone(team)
        self.assertFalse(self.account.person_in_team('TeamB'))

    def test_add_to_multiple_teams(self):
        Person.objects.create(name='TeamB')
        call_command('add_to_team', 'TeamA', 'TeamB',
                     email='test@canonical.com')
        self.assertTrue(self.account.person_in_team('TeamA'))
        self.assertTrue(self.account.person_in_team('TeamB'))

    @patch('sys.exit')
    def test_add_unknown_email(self, mock_sys_exit):
        stderr = StringIO()
        call_command('add_to_team', 'TeamA', email='foo@bar.com',
                     stderr=stderr)
        mock_sys_exit.called_once_with(1)
        stderr.seek(0)
        output = stderr.read()
        self.assertIn("Error: Email 'foo@bar.com' does not exist", output)

    @patch('sys.exit')
    def test_add_unknown_openid(self, mock_sys_exit):
        stderr = StringIO()
        call_command('add_to_team', 'TeamA', openid='foobar', stderr=stderr)
        mock_sys_exit.assert_called_once_with(1)
        stderr.seek(0)
        output = stderr.read()
        self.assertIn("Error: Account with openid 'foobar' does not exist",
                      output)

    @patch('sys.exit')
    def test_add_no_team(self, mock_sys_exit):
        stderr = StringIO()
        call_command('add_to_team', stderr=stderr)
        mock_sys_exit.assert_called_once_with(1)
        stderr.seek(0)
        output = stderr.read()
        self.assertIn('Error: Need to specify --email or --openid', output)
