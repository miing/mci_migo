# Copyright 2013 Canonical Ltd.
# This software is licensed under the GNU Affero General Public License
# version 3 (see the file LICENSE).

import os

import sst.actions
import sst.runtests
from u1testutils.sso import client, data

from identityprovider.tests.acceptance.shared import pages


class IdentityProviderSSTTestCase(sst.runtests.SSTTestCase):
    """Base test case for Identity Provider acceptance tests.

    On set up, this test case will navigate to the LogIn page, that will be
    accessible for the tests from the page attribute.

    """

    def __init__(self, methodName='runTest'):
        super(IdentityProviderSSTTestCase, self).__init__(methodName)
        self.base_url = os.environ['SST_BASE_URL']
        self.target_server = self._get_target_server()

    def setUp(self):
        super(IdentityProviderSSTTestCase, self).setUp()
        self.page = self.navigate_to_page()

    def _get_target_server(self):
        """Return the name of the target server."""
        url = self.base_url.rstrip('/')
        if url in ('https://login.staging.ubuntu.com',
                   'https://login.staging.launchpad.net'):
            target = 'staging'
        elif url in ('https://login.ubuntu.com',
                     'https://login.launchpad.net'):
            target = 'production'
        else:
            target = 'devel'
        return target

    def navigate_to_page(self):
        """Navigate to the page that will be tested, and return it.

        This method will be called during the test set up, and the page will be
        accessible for the tests from the page attribute.

        """
        sst.actions.go_to(self.base_url)
        return pages.LogIn()


class SSTTestCaseWithLogIn(IdentityProviderSSTTestCase):
    """Base test case for tests that require a logged in user.

    On set up, this test case will navigate to the YourAccount page, that will
    be accessible for the tests from the page attribute.

    On devel and staging environments, this test case will create a new user.
    On production it will use the test user specified in the config file.

    You can log in with a specific user passing it as parameter on the
    constructor. It must have the attributes full_name, email and password.
    A suggested data class is defined in the u1testutils.sso.data module.

    """

    def __init__(self, methodName='runTest', user=None):
        super(SSTTestCaseWithLogIn, self).__init__(methodName)
        if user is None:
            self.user = self._get_test_user()
        else:
            self.user = user

    def _get_test_user(self):
        if self.target_server in ('devel', 'staging'):
            user = data.User.make_from_configuration(
                new_user=True)
            # As we are using an email address that's whitelisted for the
            # captcha verification, it doesn't matter what values we send for
            # it, as long as we send some.
            error = 'Failed to register the user using the Ubuntu SSO API.'
            assert client.create_new_account(
                user, 'captcha id', 'captcha solution'), error
            return user
        elif self.target_server == 'production':
            # TODO as a preflight, check that this user exists.
            return data.User.make_from_configuration(
                new_user=False)
        else:
            raise ValueError('Unknown target: {0}'.format(self.target_server))

    def navigate_to_page(self):
        """Do the log in and go to the YourAccount page.

        It will be accessible for the tests from the page attribute.

        """
        # Start from where the base test case leaves us, the LogIn page.
        start_page = super(SSTTestCaseWithLogIn, self).navigate_to_page()
        return start_page.log_in_to_site_recognized(self.user)
