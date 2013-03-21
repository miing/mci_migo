from identityprovider.tests.helpers import OpenIDTestCase


class SwitchUserTwiceTestCase(OpenIDTestCase):

    def test(self):
        # = Switching Users Twice =

        # If a user is already logged in when authenticating via OpenID, they
        # have the option to sign in as someone else.  This logs them out and
        # takes them to the login form.

        # By using the back button in their browser, it is possible for the
        # user to perform this action twice.  The result should be the same:
        # the user is taken to the login form.

        # To test this, we will first sign the user in.  First we'll set up the
        # OpenID consumer:
        response = self.do_openid_dance()

        # Then log in as Sample Person:

        self.assertContains(response, "_qa_ubuntu_login_button")

        response = self.login(response)
        self.assertContains(response, '_qa_rp_backlink')

        # Now lets start a second authentication request, which should take us
        # to the authentication page asking if we want to sign in as someone
        # else:

        response = self.do_openid_dance()
        title = self.title_from_response(response)
        self.assertEqual(title, 'Authenticate to ' + self.consumer_url)

        # Now log out, by saying that we are someone else:

        response = self.logout(response)
        title = self.title_from_response(response)
        self.assertEqual(title, "You have been logged out")
