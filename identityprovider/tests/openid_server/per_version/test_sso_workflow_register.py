from gargoyle.testutils import switches

from identityprovider.models.account import Account
from identityprovider.models.const import (
    AccountCreationRationale,
)
from identityprovider.tests.helpers import OpenIDTestCase


class SSOWorkflowRegisterTestCase(OpenIDTestCase):

    @switches(ALLOW_UNVERIFIED=False)
    def test(self):
        # = Launchpad Single-Signon Workflow: Registration =

        # If a user wants to use a Launchpad-SSO web site, but does not have a
        # Launchpad account, they can register directly from the login page.

        # First we will set up the helper view that lets us test the final
        # portion of the authentication process:

        # The authentication process is started by the relying party issuing a
        # checkid_setup request, sending the user to Launchpad:
        response = self.do_openid_dance()

        # When a new account is created we'll use the creation rationale
        # specified for the trust_root given by the relying party.  We will set
        # up an RP configuration that uses the UBUNTU_SHOP creation rationale:

        rationale = AccountCreationRationale.OWNER_CREATED_UBUNTU_SHOP
        self.create_openid_rp_config(
            displayname='The Ubuntu Store from Canonical',
            description=("For the Ubuntu Store, you need a Launchpad account "
                         "so we can remember your order details and keep in "
                         "touch with you about your orders."),
            creation_rationale=rationale)

        # At this point, we are at the login page.  Lets try to create a new
        # account for an email address that has already been registered. This
        # shouldn't result in an error, because we don't want to reveal
        # (non-)existing email addresses:
        data = dict(
            displayname='Tester', email=self.default_email,
            password='Testing123', passwordconfirm='Testing123',
        )
        link = self.get_from_response(
            response,
            'a[data-qa-id="create_account_link"]'
        )[0].get('href')
        response = self.client.post(link, data=data, follow=True)

        title = self.get_from_response(response, 'h1.main').text()
        self.assertEqual(title, "Account creation mail sent")

        # If we instead pick a new email address, we can register an account:

        response = self.do_openid_dance()
        data = dict(
            displayname='New User', email=self.new_email,
            password='testP4ss', passwordconfirm='testP4ss',
        )
        link = self.get_from_response(
            response,
            'a[data-qa-id="create_account_link"]'
        )[0].get('href')
        response = self.client.post(link, data=data, follow=True)

        title = self.get_from_response(response, 'h1.main').text()
        self.assertEqual(title, "Account creation mail sent")

        # The user would then check their email, and find a message.

        # Let's extract the URL from the email and follow the link:

        response = self.client.get(self.confirm_link())
        msg = 'The account for %s is ready to be created.'
        self.assertContains(response, msg % self.new_email)

        # The user has already entered their full name and password, and only
        # needs to confirm.

        response = self.client.post(self.confirm_link(), follow=True)

        # Now the user is logged in with their new account, and has been
        # directed back to the original site:

        self.assertContains(response, "rp_login_title")

        response = self.yes_to_decide(response)

        # The creation rationale has been set correctly:
        account = Account.objects.get_by_email(self.new_email)
        expected_claimed_id = (
            self.base_url + '/+id/' + account.openid_identifier)

        self.assertEqual(account.creation_rationale,
                         AccountCreationRationale.OWNER_CREATED_UBUNTU_SHOP)

        # And the response matches the new OpenID:

        info = self.complete_from_response(response, expected_claimed_id)

        self.assertEqual(info.status, 'success')
        self.assertEqual(info.endpoint.claimed_id, expected_claimed_id)

        # Since this account was created using OpenID, we will not create an
        # entry in the Person table for it -- it will only be created when
        # the user logs into Launchpad.

        self.assertTrue(account.person is None)
