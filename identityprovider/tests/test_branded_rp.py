from identityprovider.tests.helpers import FunctionalTestCase


class BrandedRPTestCase(FunctionalTestCase):

    def test(self):
        # The OpenIDRPConfig table stores information about known RPs. These
        # can be branded.
        self.create_openid_rp_config(
            displayname='Example Displayname',
            description='Example Description',
            logo='canonical-store-logo.png')

        # Now pull up the authorization screen.
        response = self.do_request(mode='checkid_setup', oid='mark_oid')

        # On this screen, we find our branding information.
        self.assertContains(response, '_qa_trusted_rp_login')

        # Then we log in to ensure the branding is still present:
        response = self.login(response)

        self.assertContains(response, '_qa_rp_backlink')
