from django.core.urlresolvers import reverse

from identityprovider.models import OpenIDRPSummary
from identityprovider.tests.helpers import OpenIDTestCase


class SSOWorkflowAuthorizeTestCase(OpenIDTestCase):

    def test_authorize(self):
        # = Launchpad Single-Signon Workflow: Authorize =

        # If a user has logged into Launchpad and then wants to log in to a
        # Launchpad-SSO web site, they are not prompted for a password.

        # First we will set up the helper view that lets us test the final
        # portion of the authentication process:

        # The authentication process is started by the relying party issuing a
        # checkid_setup request, sending the user to Launchpad.  We will
        # authenticate before starting the login procedure:
        self.login()

        # Use localhost instead of launchpad.dev because Launchpad is not
        # recorded as an OpenIDRPSummary.
        response = self.do_openid_dance(url_from='http://localhost')

        # Each OpenID authentication is recorded as an OpenIDRPSummary. This
        # user has not ever used Launchpad to authenticate with a relying party
        summaries = OpenIDRPSummary.objects.filter(
            openid_identifier=self.claimed_id)

        self.assertEqual(summaries.count(), 0)

        # At this point, the user is presented with a form asking if they want
        # to authenticate to the relying party
        title = self.title_from_response(response)
        self.assertEqual(title, 'Authenticate to http://localhost')

        # By clicking the "Sign In" button, the user is returned to the relying
        # party with their identity URL:

        response = self.yes_to_decide(response)
        info = self.complete_from_response(response, self.claimed_id)

        self.assertEqual(info.status, 'success')
        self.assertEqual(info.endpoint.claimed_id, self.claimed_id)

        # The authentication was recorded. There is a summary showing that the
        # user has used the replying part once.

        summaries = OpenIDRPSummary.objects.filter(
            openid_identifier=self.claimed_id)

        self.assertEqual(summaries.count(), 1)
        summary = summaries[0]

        self.assertEqual(summary.openid_identifier, self.claimed_id)
        self.assertEqual(summary.trust_root, 'http://localhost')
        self.assertEqual(summary.total_logins, 1)

    def test_decline(self):
        # == Declining to Authenticate ==

        # Alternatively, the user could have declined to authenticate.  This
        # time, we will cancel the authentication request:
        self.login()
        response = self.do_openid_dance()

        title = self.title_from_response(response)
        self.assertEqual(title, 'Authenticate to ' + self.consumer_url)
        token = response.context['token']
        response = self.client.get(reverse('cancel', kwargs=dict(token=token)),
                                   follow=True)

        info = self.complete_from_response(response, self.claimed_id)

        self.assertEqual(info.status, 'cancel')
