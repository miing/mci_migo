from identityprovider.models.account import Account
from identityprovider.tests import DEFAULT_USER_PASSWORD
from identityprovider.tests.utils import SSOBaseTestCase
from identityprovider.utils import add_user_to_team


class PreflightViewAccessTestCase(SSOBaseTestCase):

    fixtures = ["test"]
    URL = '/preflight/'

    def test_non_authenticated_users_are_getting_404(self):
        r = self.client.get(self.URL)
        self.assertEqual(r.status_code, 404)

    def test_account_without_person_receives_404(self):
        account = Account.objects.create_account(
            "test", "abcd@example.com", DEFAULT_USER_PASSWORD)
        self.client.login(username="abcd@example.com",
                          password=DEFAULT_USER_PASSWORD)
        r = self.client.get(self.URL)
        self.assertEqual(r.status_code, 404)
        account.emailaddress_set.all().delete()
        account.delete()

    def test_person_not_in_the_required_team_will_get_404(self):
        self.client.login(username="test@canonical.com",
                          password=DEFAULT_USER_PASSWORD)
        r = self.client.get(self.URL)
        self.assertEqual(r.status_code, 404)

    def test_person_in_ubuntu_team_can_access_the_page(self):
        # add person to team
        account = Account.objects.get_by_email('member@canonical.com')
        team_name = 'ubuntu-team'
        add_user_to_team(account, team_name)

        condition_set = 'identityprovider.gargoyle.LPTeamConditionSet(lp_team)'
        self.conditionally_enable_flag('PREFLIGHT', 'team', team_name,
                                       condition_set)
        # test flag
        self.client.login(username="member@canonical.com",
                          password=DEFAULT_USER_PASSWORD)
        r = self.client.get(self.URL)

        self.assertTemplateUsed(r, "preflight/overview.html")
