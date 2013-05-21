from django.core.management import call_command, CommandError
from django.test import TestCase

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

    def test_add_unknown_email(self):
        with self.assertRaises(CommandError) as cm:
            call_command('add_to_team', 'TeamA', email='foo@bar.com')

        self.assertEqual("Email 'foo@bar.com' does not exist",
                         str(cm.exception))

    def test_add_unknown_openid(self):
        with self.assertRaises(CommandError) as cm:
            call_command('add_to_team', 'TeamA', openid='foobar')
        self.assertEqual("Account with openid 'foobar' does not exist",
                         str(cm.exception))

    def test_add_no_team(self):
        with self.assertRaises(CommandError) as cm:
            call_command('add_to_team')
        self.assertEqual('Need to specify --email or --openid',
                         str(cm.exception))
