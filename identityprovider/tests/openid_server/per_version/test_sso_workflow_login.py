from identityprovider.tests.helpers import OpenIDTestCase


class SSOWorkflowLoginTestCase(OpenIDTestCase):

    def test(self):
        # = Launchpad Single-Signon Workflow: Login =

        # A user with an existing account may log into a Launchpad-SSO web site
        # simply by entering their password on the login site.

        # First we will set up the helper view that lets us test the final
        # portion of the authentication process:

        # The authentication process is started by the relying party issuing a
        # checkid_setup request, sending the user to Launchpad:
        response = self.do_openid_dance()

        # As the user already has an account, they can enter their email
        # address and password. The user must enter a valid email address, or
        # they will receive an error:
        response = self.login(response, email='not an email address')
        error = self.get_from_response(response, 'span.error').text()
        self.assertEqual(error, "Invalid email.")

        # Leaving the email address field blank results in the same error:

        response = self.login(response, email='')
        error = self.get_from_response(response, 'span.error').text()
        self.assertEqual(error, "Required field.")

        # If the user provides a non-ASCII password, they receive an incorrect
        # password error.

        response = self.login(response, password='\xc2\xa0blah')
        error = self.get_from_response(response, 'span.error').text()
        self.assertEqual(error, "Password didn't match.")

        # If the password does not match the given email address, an error is
        # shown:

        response = self.login(response, password='not the password')
        error = self.get_from_response(response, 'span.error').text()
        self.assertEqual(error, "Password didn't match.")

        # Finally, if the email address and password match, the user is logged
        # in and returned to the relying party, with the user's identity URL:

        response = self.login(response)
        error = self.get_from_response(response, 'span.error')
        self.assertEqual(len(error), 0)

        link_text = self.get_from_response(
            response, 'a[href="%s"]' % self.consumer_url)[0].text
        self.assertEqual(link_text, self.consumer_url)

        response = self.yes_to_decide(response)

        info = self.complete_from_response(response, self.claimed_id)

        self.assertEqual(info.status, 'success')
        self.assertEqual(info.endpoint.claimed_id, self.claimed_id)
