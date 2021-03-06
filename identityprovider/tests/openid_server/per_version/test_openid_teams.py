from identityprovider.const import LAUNCHPAD_TEAMS_NS
from identityprovider.tests.helpers import OpenIDTestCase


class OpenIDTeamsTestCase(OpenIDTestCase):

    def test(self):
        # = Launchpad OpenID Teams Extension =

        # The Launchpad OpenID server implements a custom team membership
        # extension.  This allows a relying party to query whether the user is
        # a member of one or more teams.

        # Now perform an OpenID authentication request, querying membership in
        # four team names:
        #  * one that the user is a member of
        #  * one that does not exist
        #  * one that does exist but the user is not a member of
        #  * one that is actually the user's name

        t = self.factory.make_team('ubuntu-team')
        self.factory.add_account_to_team(self.account, t)

        self.factory.make_team('launchpad-beta-testers')

        teams = ('ubuntu-team,no-such-team,launchpad-beta-testers,%s' %
                 self.account.person.name)
        response = self.do_openid_dance(self.claimed_id, teams=teams)
        response = self.login(response)
        # authorize sending team membership
        response = self.yes_to_decide(response, teams=('ubuntu-team',))
        info = self.complete_from_response(response)

        self.assertEqual(info.status, 'success')
        self.assertEqual(info.getSigned(LAUNCHPAD_TEAMS_NS, 'is_member'),
                         'ubuntu-team')

        # The response reveals that the user is a member of the ubuntu-team.
        # As specified, there is no difference in the response for non-existent
        # teams and teams that the user is not a member of.
