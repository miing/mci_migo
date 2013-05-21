from identityprovider.models.account import Account
from identityprovider.tests import DEFAULT_USER_PASSWORD
from identityprovider.tests.utils import SSOBaseTestCase


class PreflightViewAccessTestCase(SSOBaseTestCase):

    URL = '/preflight/'

    def setUp(self):
        super(PreflightViewAccessTestCase, self).setUp()
        self.team_name = 'ubuntu-team'
        condition_set = 'identityprovider.gargoyle.LPTeamConditionSet(lp_team)'
        self.conditionally_enable_flag(
            'PREFLIGHT',
            'team',
            self.team_name,
            condition_set
        )

    def test_non_authenticated_users_are_getting_404(self):
        r = self.client.get(self.URL)
        self.assertEqual(r.status_code, 404)

    def test_account_without_person_receives_404(self):
        account = Account.objects.create_account(
            "test", "abcd@example.com", DEFAULT_USER_PASSWORD)
        self.client.login(username=account.preferredemail.email,
                          password=DEFAULT_USER_PASSWORD)
        r = self.client.get(self.URL)
        self.assertEqual(r.status_code, 404)

    def test_person_not_in_the_required_team_will_get_404(self):
        account = self.factory.make_account(
            email="test@canonical.com", password=DEFAULT_USER_PASSWORD)
        self.client.login(username=account.preferredemail.email,
                          password=DEFAULT_USER_PASSWORD)
        r = self.client.get(self.URL)
        self.assertEqual(r.status_code, 404)

    def test_person_in_ubuntu_team_can_access_the_page(self):
        account = self.factory.make_account(
            teams=[self.team_name], password=DEFAULT_USER_PASSWORD)

        # test flag
        self.client.login(username=account.preferredemail.email,
                          password=DEFAULT_USER_PASSWORD)
        r = self.client.get(self.URL)

        self.assertTemplateUsed(r, "preflight/overview.html")
