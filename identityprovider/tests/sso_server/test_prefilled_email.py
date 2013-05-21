from identityprovider.tests.helpers import FunctionalTestCase


class PrefilledEmailTestCase(FunctionalTestCase):
    """Pre-fill e-mail addresses on forms.

    If the user has attempted a login (and failed), we would like to use the
    e-mail provided to pre-fill other forms.

    """

    def test_forgot_password(self):
        """Forgot Password form."""
        response = self.login(email=self.new_email)

        link = self.get_attribute_from_response(
            response,
            'a[data-qa-id="forgot_password_link"]',
            'href')

        response = self.client.get(link)
        email_field = self.get_from_response(response, 'input[name="email"]')
        self.assertEqual(email_field[0].get('value'), self.new_email)

    def test_new_account(self):
        """New Account form."""
        response = self.login(email=self.new_email)

        link = self.get_attribute_from_response(
            response,
            'a[data-qa-id="create_account_link"]',
            'href')

        response = self.client.get(link)
        email_field = self.get_from_response(response, 'input[name="email"]')
        self.assertEqual(email_field[0].get('value'), self.new_email)
