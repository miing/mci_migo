from django.core.urlresolvers import reverse

from identityprovider.tests.helpers import OpenIDTestCase


class LogoutDuringLoginTestCase(OpenIDTestCase):

    def test(self):
        # = Handling Logouts During the Login Process =

        # If the user is logged in when the OpenID authentication request
        # begins, they are presented with a form that asks them if they want to
        # agree to log in to the remote site, without entering their password a
        # second time.

        # Now if the user manages to log out before posting this form, we can
        # not authenticate them to the remote site.  If this occurs, the user
        # should instead be prompted to log in.

        # There are a number of ways that this situation could occur:

        #  1. The user logs out in another browser window or tab.
        #  2. The user clicks the "I'm someone else" button, uses the browser's
        #     back button, then resubmits the form.

        # To test this, we will first authenticate to the Launchpad OpenID
        # provider:
        claimed_id = self.base_url + '/+id/name12_oid'
        response = self.do_openid_dance(claimed_id)

        response = self.yes_to_decide(self.login(response))
        info = self.complete_from_response(response)

        self.assertEqual(info.status, 'success')
        self.assertEqual(info.endpoint.claimed_id, claimed_id)

        # Now lets begin another OpenID authentication request, which will
        # present a different form asking if we want to authenticate:
        response = self.do_openid_dance(claimed_id)

        title = self.title_from_response(response)
        self.assertEqual(title, 'Authenticate to ' + self.consumer_url)

        # store the token to later be able to properly reverse the login url
        token = response.context['token']

        # We will now log out using the "Log Out" button, which will
        # present us with the login form.  We will then go back to the first
        # page:
        response = self.logout(response)
        title = self.title_from_response(response)
        self.assertEqual(title, "You have been logged out")

        response = self.client.get(reverse('login', kwargs=dict(token=token)))
        title = self.title_from_response(response)
        self.assertEqual(title, 'Log in')

        # From this point, we can log in as usual:
        response = self.login(response)
        response = self.yes_to_decide(response)
        info = self.complete_from_response(response)

        self.assertEqual(info.status, 'success')
        self.assertEqual(info.endpoint.claimed_id, claimed_id)
