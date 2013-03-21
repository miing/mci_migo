from django.utils.unittest import TestCase
from gargoyle import gargoyle

from identityprovider.gargoyle import (
    LPTeamConditionSet,
    Regex,
    Team,
)
from identityprovider.models.account import Account
from identityprovider.models.const import EmailStatus
from identityprovider.tests.utils import SSOBaseTestCase


class TestTeam(TestCase):

    def test_is_active_team_not_found(self):
        condition = 'my-team'
        value = ['team1', 'team2']
        self.assertFalse(Team(condition).is_active(condition, value))

    def test_is_active_no_teams(self):
        condition = 'my-team'
        value = []
        self.assertFalse(Team(condition).is_active(condition, value))

    def test_is_active_team_found(self):
        condition = 'my-team'
        value = ['team1', 'my-team']
        self.assertTrue(Team(condition).is_active(condition, value))


class LPTeamConditionSetTestCase(SSOBaseTestCase):

    def setUp(self):
        super(LPTeamConditionSetTestCase, self).setUp()
        self.conditions = LPTeamConditionSet(Account)

    def test_get_namespace(self):
        self.assertEqual(self.conditions.get_namespace(), 'lp_team')

    def test_get_group_label(self):
        self.assertEqual(self.conditions.get_group_label(), 'LP Team')

    def test_can_execute(self):
        account = self.factory.make_account()
        self.assertTrue(self.conditions.can_execute(account))

    def test_can_execute_no_account(self):
        self.assertFalse(self.conditions.can_execute(None))

    def test_get_field_value_wrong_field_name(self):
        expected = []
        account = self.factory.make_account()
        team = self.factory.make_team('team1')
        self.factory.add_account_to_team(account, team)

        self.assertEqual(
            self.conditions.get_field_value(account, 'foo'), expected)

    def test_get_field_value_no_person(self):
        expected = []
        account = self.factory.make_account()

        self.assertEqual(
            self.conditions.get_field_value(account, 'team'), expected)

    def test_get_field_value_person(self):
        expected = ['team1']
        account = self.factory.make_account()
        team = self.factory.make_team('team1')
        self.factory.add_account_to_team(account, team)

        self.assertEqual(
            self.conditions.get_field_value(account, 'team'), expected)
        self.assertTrue(account.person.in_team('team1'))


class AccountConditionSetTestCase(SSOBaseTestCase):

    key_name = 'test'

    def setUp(self):
        super(AccountConditionSetTestCase, self).setUp()
        condition_set = ('identityprovider.gargoyle.'
                         'AccountConditionSet(identityprovider.account)')
        self.conditionally_enable_flag(
            self.key_name, 'email', 'isdtest\+.*@canonical\.com',
            condition_set)
        self.account = self.factory.make_account()

    def test_is_active_no_preferred_email(self):
        self.account.preferredemail.status = EmailStatus.VALIDATED
        self.assertFalse(gargoyle.is_active(self.key_name, self.account))

    def test_is_active_preferred_email_not_matching(self):
        self.assertNotEqual(self.account.preferredemail, None)
        self.assertFalse(gargoyle.is_active(self.key_name))

    def test_is_active_preferred_email_matching(self):
        email = self.factory.make_email_for_account(
            self.account, 'isdtest+test@canonical.com', EmailStatus.PREFERRED)
        self.account.preferredemail = email
        self.assertTrue(gargoyle.is_active(self.key_name, self.account))

    def test_is_active_preferred_email_is_none(self):
        self.account.emailaddress_set.all().delete()
        self.assertEqual(self.account.preferredemail, None)

        account = Account.objects.get(id=self.account.id)
        self.assertFalse(gargoyle.is_active(self.key_name, account))

    def test_is_active_non_validated_email(self):
        self.factory.make_email_for_account(
            self.account, 'isdtest+test@canonical.com', EmailStatus.NEW)
        self.assertTrue(gargoyle.is_active(self.key_name, self.account))


class RegexTestCase(TestCase):

    def setUp(self):
        super(RegexTestCase, self).setUp()
        self.field = Regex()
        self.condition = u'isdtest(\\+[^@]*)?@canonical\\.com'

    def test_is_active_match(self):
        result = self.field.is_active(self.condition,
                                      'isdtest+foo@canonical.com')
        self.assertTrue(result)

    def test_is_active_no_match(self):
        result = self.field.is_active(self.condition, 'foo@foo.com')
        self.assertFalse(result)

    def test_is_active_null_value(self):
        result = self.field.is_active(self.condition, None)
        self.assertFalse(result)

    def test_is_active_multiple_values(self):
        emails = ['isdtest+foo@canonical.com', 'someother@example.com']
        result = self.field.is_active(self.condition, emails)
        self.assertTrue(result)
