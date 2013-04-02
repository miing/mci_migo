from openid.extensions import pape

from identityprovider.tests.helpers import OpenIDTestCase


class MaxAuthAgeTestCase(OpenIDTestCase):

    def test(self):
        # = OpenID Security Extensions: Max Auth Age =

        # SSO supports the max_auth_age extension parameter defined in
        # Provider Authentication Policy Extension (
        # http://openid.net/specs/ \
        # openid-provider-authentication-policy-extension-1_0-07.html).
        # It offers a way for a relaying party to ensure that the user enters
        # their password, even if they have already logged into the site. The
        # purpose of this is for sites for which the long-lived session policy
        # is problematic.

        response = self.login()
        self.assert_home_page(response)

        # Normally, if a relaying party asks to authenticates this user, the
        # user will be able to click the 'Sign In' button to complete the
        # authentication process.
        response = self.do_openid_dance(self.base_url, with_discovery=True)

        # The max_auth_age PAPE parameter can be used to force the user to
        # enter their password, even if they are already authenticated with
        # Launchpad.

        # Using 0 as max_auth_age value will always force the user to enter
        # their password.
        pape_request = pape.Request(max_auth_age=0)
        response = self.do_openid_dance(self.base_url, with_discovery=True,
                                        extension=pape_request)

        self.assertRegexpMatches(response.redirect_chain[-1][0],
                                 self.base_url + '/.*?/\+decide')

        self.assertNotContains(response, self.account.displayname)

        # Since we know who the user is, the email field is pre-filled for
        # their convenience:

        response = self.login(response)
        response = self.yes_to_decide(response)

        info = self.complete_from_response(response, self.claimed_id)

        self.assertEqual(info.status, 'success')
        self.assertEqual(info.endpoint.claimed_id, self.claimed_id)

        # The auth_age parameter contains the time of the last login.
        pape_response = pape.Response.fromSuccessResponse(info)

        self.assertRegexpMatches(pape_response.auth_time, '2.*')
