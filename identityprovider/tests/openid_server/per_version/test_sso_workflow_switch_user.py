from identityprovider.tests.helpers import OpenIDTestCase


class SSOWorkflowSwitchUserTestCase(OpenIDTestCase):

    def test(self):
        # = Launchpad Single-Signon Workflow: Switching Users =

        # If a user is making use of a public or shared computer, and wants to
        # log into a Launchpad-SSO website, they may find that someone else has
        # logged into Launchpad.  In this case, the user can log out and then
        # back in as part of the authentication process.

        # First we will set up the helper view that lets us test the final
        # portion of the authentication process:

        # We will first authenticate as Mark Shuttleworth:
        response = self.do_openid_dance()
        self.yes_to_decide(self.login(response, email='mark@example.com'))

        # Now lets imagine that test@canonical.com starts using the computer
        # and wishes to log into a Launchpad-SSO web site. They will be asked
        # if they want to authenticate as Mark Shuttleworth:

        response = self.do_openid_dance()
        title = self.title_from_response(response)
        self.assertEqual(title, 'Authenticate to ' + self.consumer_url)
        self.assertContains(response, 'Mark Shuttleworth')

        # At this point, the user says that they are not Mark Shuttleworth,
        # which presents them with a login page:

        response = self.logout(response)
        title = self.title_from_response(response)
        self.assertEqual(title, "You have been logged out")

        # They can now log in as test@canonical.com, and the appropriate
        # identity URL will be sent to the relying party:

        # Then we run the test
        response = self.do_openid_dance()
        response = self.yes_to_decide(self.login(response))
        claimed_id = self.base_url + '/+id/name12_oid'
        info = self.complete_from_response(response, claimed_id)

        self.assertEqual(info.status, 'success')
        self.assertEqual(info.endpoint.claimed_id, claimed_id)
