from identityprovider.const import LAUNCHPAD_TEAMS_NS
from identityprovider.models.const import AccountCreationRationale
from identityprovider.models.openidmodels import OpenIDRPConfig
from identityprovider.tests.helpers import OpenIDTestCase


class OpenIDTeamsPrivateMembershipTestCase(OpenIDTestCase):

    def setUp(self):
        super(OpenIDTeamsPrivateMembershipTestCase, self).setUp()
        t = self.factory.make_team(name='myteam', private=True)
        self.factory.add_account_to_team(self.account, t)

    def test_untrusted_rps(self):
        # = Launchpad OpenID Teams Extension Restrictions on Private Teams =

        # The Launchpad OpenID Teams Extension provides a way for relying
        # parties to check a user's team membership.  Launchpad also supports
        # the concept of private membership teams.  We do not want Launchpad's
        # OpenID code to disclose details of private membership teams to
        # unauthorized RPs.

        # The sample data contains a private team called "myteam", which has a
        # member called "member".

        # Let's set up an OpenID authentication request for this user,
        # checking to see whether they are a member of "myteam".  First we'll
        # set up the consumer:
        assert OpenIDRPConfig.objects.count() == 0

        # Now perform the authentication request, using the teams extension to
        # query membership of "myteam":

        auth = 'Basic %s:%s' % (self.default_email, self.default_password)
        response = self.do_openid_dance(
            self.claimed_id, teams='myteam', HTTP_AUTHORIZATION=auth)

        response = self.login(response)
        # make sure the user doesn't have the option to authorize the
        # team, as it's private
        myteam = self.get_from_response(
            response, 'input[type="checkbox"][value="myteam"]')
        self.assertEqual(len(myteam), 0)

        # The authentication request is successful:
        response = self.yes_to_decide(response)
        info = self.complete_from_response(response)

        self.assertEqual(info.status, 'success')

        # The authentication response includes a list of the teams the user is
        # a member of.  As "myteam" is private, Launchpad has not disclosed the
        # user's membership to the RP:

        self.assertEqual(info.getSigned(LAUNCHPAD_TEAMS_NS, 'is_member'), '')

    def test_trusted_rps(self):
        # == Trusted RPs ==

        # If the RP is known to Launchpad by having an OpenIDRPConfig and
        # flagged as being able to query private team membership (the
        # IOpenIDRPConfig.can_query_any_team flag), then it is allowed to do
        # so. To test this, lets create an RP config:

        rpconfig = self.create_openid_rp_config(
            displayname='Test RP', description="A test RP",
            creation_rationale=AccountCreationRationale.USER_CREATED)

        # Now perform a second authentication request:

        response = self.do_openid_dance(self.claimed_id, teams='myteam')

        response = self.login(response)
        # make sure the user doesn't have the option to authorize the
        # team, as it's private
        myteam = self.get_from_response(
            response, 'input[type="checkbox"][value="myteam"]')
        self.assertEqual(len(myteam), 0)

        # The authentication request is successful:
        response = self.yes_to_decide(response)
        info = self.complete_from_response(response)

        self.assertEqual(info.status, 'success')

        # However, even though the RP is known, it hasn't been given permission
        # to query private teams:

        self.assertEqual(info.getSigned(LAUNCHPAD_TEAMS_NS, 'is_member'), '')

        # So lets set the can_query_any_team flag on our RP config:

        rpconfig.can_query_any_team = True
        rpconfig.save()

        # Now if we authenticate again, Launchpad will informed us that
        # "member" is a member of "myteam":

        response = self.do_openid_dance(self.claimed_id, teams='myteam')
        myteam = self.get_from_response(
            response, 'input[type="checkbox"][value="myteam"]')
        self.assertEqual(len(myteam), 1)

        # authorize sending membership info
        response = self.yes_to_decide(response, teams=('myteam',))
        info = self.complete_from_response(response)

        self.assertEqual(info.status, 'success')
        self.assertEqual(info.getSigned(LAUNCHPAD_TEAMS_NS, 'is_member'),
                         'myteam')
