from identityprovider.const import LAUNCHPAD_TEAMS_NS
from identityprovider.tests.helpers import OpenIDTestCase


class OpenIDTeamsAutoAuthorizeTestCase(OpenIDTestCase):

    def test(self):
        # = Interaction of Launchpad OpenID Teams with Auto-Authorize =
        # Check that teams work well when requested by an auto-authorized RP.
        self.create_openid_rp_config(
            displayname='Test RP', description='A test RP',
            auto_authorize=True, can_query_any_team=True)

        # Now perform an OpenID authentication request, querying membership in
        # four team names:
        #  * one that the user is a member of and is public
        #  * one that the user is a member of, but is private
        #  * one that does not exist
        #  * one that does exist but the user is not a member of

        t = self.factory.make_team(name='ubuntu-team')
        self.factory.add_account_to_team(self.account, t)

        t = self.factory.make_team(name='myteam', private=True)
        self.factory.add_account_to_team(self.account, t)

        self.factory.make_team('launchpad-beta-testers')

        teams = 'ubuntu-team,no-such-team,launchpad-beta-testers,myteam'
        response = self.do_openid_dance(self.claimed_id, teams=teams)
        response = self.login(response)
        info = self.complete_from_response(response)

        self.assertEqual(info.status, 'success')
        self.assertEqual(
            set(info.getSigned(LAUNCHPAD_TEAMS_NS, 'is_member').split(',')),
            set('ubuntu-team,myteam'.split(',')))

        # The response reveals that the user is a member of the ubuntu-team,
        # and myteam as it's allowed to query private teams too.
