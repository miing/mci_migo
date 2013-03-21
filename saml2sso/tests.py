###################################################################
#
# Copyright (c) 2012 Canonical Ltd.
# Copyright (c) 2013 Miing.org <samuel.miing@gmail.com>
# 
# This software is licensed under the GNU Affero General Public 
# License version 3 (AGPLv3), as published by the Free Software 
# Foundation, and may be copied, distributed, and modified under 
# those terms.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# file LICENSE for more details.
#
###################################################################

"""
Tests for SAML2 Processors.

A lot of this is borrowed directly from the saml2idp tests.
"""

import base64
import copy

from django.conf import settings
from django.test.client import Client
from gargoyle.models import GLOBAL, Switch
from gargoyle.testutils import switches
from mock import patch
from pyquery import PyQuery
from saml2idp import saml2idp_metadata
from saml2idp.tests import salesforce, google_apps
from saml2idp.urls import deeplink_url_patterns

import identityprovider.urls

from identityprovider.gargoyle import LPTeamConditionSet
from identityprovider.models.const import EmailStatus
from identityprovider.models import Account, EmailAddress, OpenIDRPConfig
from identityprovider.tests import DEFAULT_USER_PASSWORD
from identityprovider.tests.utils import AuthenticatedTestCase
from identityprovider.utils import add_user_to_team


SAML_TEAM = 'saml2team'  # Name of team enabled for SAML 2.0


def add_test_user_to_saml_team(address):
    """
    Adds test user with email address to the SAML_TEAM.
    """
    email = EmailAddress.objects.get(email=address)
    add_user_to_team(email.account, SAML_TEAM)


def find_cert_path():
    """
    Find the right path to certificates
    """
    from identityprovider import tests
    return tests.__path__[0] + '/cert/'


def change_preferred_email(login_email, alternate_email):
    """
    Finds the user identified by login_email and sets his preferredemail to
    alternate_email.
    """
    email = EmailAddress.objects.get(email=login_email)
    account = email.account
    target = EmailAddress.objects.get(email=alternate_email)
    account.preferredemail = target
    return account


def get_saml_response(response):
    tree = PyQuery(response.content)
    inputtag = tree.find('input[name="SAMLResponse"]')
    assert len(inputtag) == 1
    encoded_response = inputtag[0].get('value')
    samlresponse = base64.b64decode(encoded_response)
    return samlresponse


class GoogleAppsAssertionTestCase(AuthenticatedTestCase):
    """
    Test SAML Assertions for a Google Apps Service Point.

    Sub-classes with identical behavior, but different ACS_URL or REQUEST_DATA
    simply specify their own attributes on the class.
    """
    ACS_URL = google_apps.GOOGLE_APPS_ACS
    REQUEST_DATA = google_apps.REQUEST_DATA
    PROCESSOR = 'saml2sso.processors.GoogleAppsProcessor'

    def setUp(self, *args, **kwargs):
        super(GoogleAppsAssertionTestCase, self).setUp(*args, **kwargs)
        # Save settings.
        _old_saml2idp_config = copy.deepcopy(saml2idp_metadata.SAML2IDP_CONFIG)
        path = find_cert_path()
        cert_file = path + 'certificate.pem'
        priv_file = path + 'private-key.pem'
        test_config = {
            'certificate_file': cert_file,
            'private_key_file': priv_file,
            'signing': True,
        }
        saml2idp_metadata.SAML2IDP_CONFIG.update(test_config)
        # Restore settings.
        self.addCleanup(setattr, saml2idp_metadata, 'SAML2IDP_CONFIG',
                        _old_saml2idp_config)

        saml2idp_metadata.SAML2IDP_REMOTES['foobar'] = {
            'acs_url': self.ACS_URL,
            'processor': self.PROCESSOR,
        }
        self.addCleanup(saml2idp_metadata.SAML2IDP_REMOTES.pop, 'foobar')

        condition_set = 'identityprovider.gargoyle.LPTeamConditionSet(lp_team)'
        self.conditionally_enable_flag(
            'SAML2', 'team', SAML_TEAM, condition_set)

        # enable TWOFACTOR flag
        switch = Switch.objects.create(key='TWOFACTOR', status=GLOBAL)
        self.addCleanup(switch.delete)

        # mock twofactor auth
        self.mock_authenticate_device = patch(
            # XXX: should not depend on webui
            'webui.views.ui.authenticate_device')
        self.mock_authenticate_device.start()
        self.addCleanup(self.mock_authenticate_device.stop)

    def test_authnrequest_handled(self):
        """ AuthnRequest isn't handled by a Processor. """
        # Arrange/Act:
        response = self.client.get('/+saml', data=self.REQUEST_DATA,
                                   follow=False)

        # Assert:
        self.assertEqual(response.status_code, 302)

    def test_authnrequest_csrf_exempt(self):
        client = Client(enforce_csrf_checks=True)
        response = client.post('/+saml', data=self.REQUEST_DATA,
                               follow=False)
        self.assertEqual(response.status_code, 302)

    def test_user_logged_in(self):
        """ Unable to produce a valid Assertion for SAML 2-enabled user. """
        # Act:
        add_test_user_to_saml_team(self.login_email)
        # upgrade to 2f session
        response = self.client.post('/two_factor_auth',
                                    {'oath_token': '123456'})
        response = self.client.get('/+saml', data=self.REQUEST_DATA,
                                   follow=True)
        samlresponse = get_saml_response(response)

        # Assert:
        self.assertTrue(self.login_email in samlresponse)

    def test_user_has_different_preferred_email(self):
        """ User's preferred email is not being passed as SAML identifier. """
        # make sure no @canonical.com email address is used so the preferred
        # email is returned
        self.login_email = 'mark@example.com'
        self.factory.make_account(email=self.login_email)
        self.client.login(username=self.login_email,
                          password=self.login_password)
        # Act:
        add_test_user_to_saml_team(self.login_email)
        # upgrade to 2f session
        response = self.client.post('/two_factor_auth',
                                    {'oath_token': '123456'})
        account = Account.objects.get_by_email(self.login_email)
        # create alternate email
        # and make sure the email is linked to the account
        alternate_email = 'alternate@example.com'
        alternate, _ = EmailAddress.objects.get_or_create(
            email=alternate_email, defaults={'account': account,
                                             'status': EmailStatus.VALIDATED})
        # and make the alternate email the preferred
        account = change_preferred_email(self.login_email, alternate_email)
        self.assertEqual(account.preferredemail, alternate)
        response = self.client.get('/+saml', data=self.REQUEST_DATA,
                                   follow=True)
        samlresponse = get_saml_response(response)

        # Assert:
        self.assertTrue(alternate_email in samlresponse)

    def test_user_not_enabled(self):
        """ Assertion produced for user who is not enabled for SAML 2.0. """
        # Arrange/Act:
        # upgrade to 2f session
        response = self.client.post('/two_factor_auth',
                                    {'oath_token': '123456'})
        response = self.client.get('/+saml', data=self.REQUEST_DATA,
                                   follow=True)

        # Assert:
        self.assertTemplateUsed(response, 'saml2idp/invalid_user.html')

    def test_user_not_2f_but_no_rpconfig(self):
        response = self.client.get('/+saml', data=self.REQUEST_DATA)

        self.assertEqual(response.status_code, 302)
        self.assertTrue('/+saml/process' in response['Location'])

    def test_user_not_2f_but_rpconfig_without_flag(self):
        OpenIDRPConfig.objects.create(trust_root=self.ACS_URL)

        response = self.client.get('/+saml', data=self.REQUEST_DATA)

        self.assertEqual(response.status_code, 302)
        self.assertTrue('/+saml/process' in response['Location'])

    def test_user_not_2f_but_not_required(self):
        OpenIDRPConfig.objects.create(trust_root=self.ACS_URL,
                                      flag_twofactor='SAML_TWOFACTOR')

        with switches(SAML_TWOFACTOR=False):
            response = self.client.get('/+saml', data=self.REQUEST_DATA)

        self.assertEqual(response.status_code, 302)
        self.assertTrue('/+saml/process' in response['Location'])

    def test_user_not_2f_but_required(self):
        # make sure the rpconfig entry requires 2f
        OpenIDRPConfig.objects.create(trust_root=self.ACS_URL,
                                      flag_twofactor='SAML_TWOFACTOR')

        with switches(SAML_TWOFACTOR=True):
            response = self.client.get('/+saml', data=self.REQUEST_DATA,
                                       follow=True)

        # make sure the last redirect was for twofactor
        self.assertIn('/two_factor_auth', response.redirect_chain[-1][0])

    def setup_saml_emails(self, prefer_canonical_email=False):
        add_test_user_to_saml_team(self.login_email)
        # add @canonical.com email address to the account
        account = EmailAddress.objects.get(email=self.login_email).account
        EmailAddress.objects.create(
            email='first.last@canonical.com',
            account=account, status=EmailStatus.VALIDATED)
        # create an RP that prefers @canonical emails
        OpenIDRPConfig.objects.create(
            trust_root=self.ACS_URL,
            prefer_canonical_email=prefer_canonical_email)

        return account.preferredemail

    def do_saml_request(self):
        # do twofactor dance
        self.client.post('/two_factor_auth', {'oath_token': '123456'})
        # do saml dance
        response = self.client.get('/+saml', data=self.REQUEST_DATA,
                                   follow=True)
        samlresponse = get_saml_response(response)
        return samlresponse

    def test_canonical_email_is_preferred(self):
        preferred = self.setup_saml_emails(prefer_canonical_email=True)
        samlresponse = self.do_saml_request()
        # verify @canonical.com email address is returned despite it's not the
        # preferredemail
        self.assertIn('first.last@canonical.com', samlresponse)
        self.assertNotEqual('first.last@canonical.com', preferred)

    def test_canonical_email_is_not_preferred(self):
        preferred = self.setup_saml_emails(prefer_canonical_email=False)
        samlresponse = self.do_saml_request()
        # verify @canonical.com email address is *not* returned despite because
        # the flag was not set
        self.assertIn(preferred.email, samlresponse)
        self.assertNotEqual('first.last@canonical.com', preferred)

    def test_canonical_email_without_rpconfig(self):
        preferred = self.setup_saml_emails()
        # make sure there is no RP for this url
        OpenIDRPConfig.objects.filter(trust_root=self.ACS_URL).delete()

        samlresponse = self.do_saml_request()
        # verify @canonical.com email address is *not* returned despite because
        # the flag was not set
        self.assertIn(preferred.email, samlresponse)
        self.assertNotEqual('first.last@canonical.com', preferred)

    def test_non_canonical_email(self):
        # prepare account for SAML
        account = self.factory.make_account()
        preferred = account.preferredemail.email
        add_test_user_to_saml_team(preferred)
        OpenIDRPConfig.objects.create(trust_root=self.ACS_URL,
                                      prefer_canonical_email=True)

        # make sure account has only one email
        assert account.emailaddress_set.count() == 1
        # and it's not a @canonical.com one
        assert '@canonical.com' not in preferred

        self.client.login(username=preferred, password=DEFAULT_USER_PASSWORD)

        samlresponse = self.do_saml_request()
        self.assertIn(preferred, samlresponse)


class SalesForceAssertionTestCase(GoogleAppsAssertionTestCase):
    """
    Test SAML Assertions for a SalesForce Service Point.
    """
    ACS_URL = salesforce.SALESFORCE_ACS
    REQUEST_DATA = salesforce.REQUEST_DATA
    PROCESSOR = 'saml2sso.processors.SalesForceProcessor'


class SalesForcePortalAssertionTestCase(SalesForceAssertionTestCase):
    ACS_URL = salesforce.SALESFORCE_ACS
    REQUEST_DATA = salesforce.REQUEST_DATA
    PROCESSOR = 'saml2sso.processors.SalesForceAttributeProcessor'

    def setUp(self, *args, **kwargs):
        super(SalesForcePortalAssertionTestCase, self).setUp(*args, **kwargs)
        target = 'https://somesite.salesforce.com/%(target)s'
        saml2idp_metadata.SAML2IDP_REMOTES['foobar']['links'] = {
            # NOTE: This doesn't match the SALESFORCE_ACS,
            # but it will in production.
            r'portal/(?P<target>\w+)': target,
        }
        self.addCleanup(saml2idp_metadata.SAML2IDP_REMOTES['foobar'].pop,
                        'links')

        # Update the site's URLs to include the new pattern.
        original_patterns = identityprovider.urls.urlpatterns
        identityprovider.urls.urlpatterns += deeplink_url_patterns(
            'saml2sso.views',
            r'^\+saml/init/%s$', 'saml_init'
        )
        self.addCleanup(setattr, identityprovider.urls, 'urlpatterns',
                        original_patterns)

        _old_portal_id = getattr(settings, 'PORTAL_ID', None)
        settings.PORTAL_ID = 'SAMPLE_PORTAL_ID'
        self.addCleanup(setattr, settings, 'PORTAL_ID', _old_portal_id)

        _old_org_id = getattr(settings, 'ORGANIZATION_ID', None)
        settings.ORGANIZATION_ID = 'SAMPLE_ORG_ID'
        self.addCleanup(setattr, settings, 'PORTAL_ID', _old_org_id)

    def test_canonical_email_is_preferred(self):
        preferred = self.setup_saml_emails(prefer_canonical_email=True)
        samlresponse = self.do_saml_request()
        self.assertIn('first.last+portal@canonical.com', samlresponse)
        self.assertNotEqual('first.last+portal@canonical.com', preferred)

    def test_non_canonical_email(self):
        # prepare account for SAML
        account = self.factory.make_account()
        preferred = account.preferredemail.email
        add_test_user_to_saml_team(preferred)
        OpenIDRPConfig.objects.create(trust_root=self.ACS_URL,
                                      prefer_canonical_email=True)

        # make sure account has only one email
        assert account.emailaddress_set.count() == 1
        # and it's not a @canonical.com one
        assert '@canonical.com' not in preferred

        self.client.login(username=preferred, password=DEFAULT_USER_PASSWORD)

        samlresponse = self.do_saml_request()
        self.assertIn(preferred, samlresponse)
        self.assertNotIn('+portal@', samlresponse)

    def test_portal_deeplink(self):
        """Unable to produce a valid Portal Assertion.

        (for SAML 2-enabled user)
        """
        # Act:
        add_test_user_to_saml_team(self.login_email)
        # upgrade to 2f session
        response = self.client.post('/two_factor_auth',
                                    {'oath_token': '123456'})
        response = self.client.get(
            '/+saml/init/portal/SOMETARGETID', data=self.REQUEST_DATA,
            follow=True)
        samlresponse = get_saml_response(response)

        tree = PyQuery(response.content)
        relsttag = tree.find('input[name="RelayState"]')
        assert len(relsttag) == 1
        relaystate = relsttag[0].get('value')

        samlsoup = PyQuery(samlresponse.replace('xmlns:', 'xmlnamespace:'))

        org_attr = samlsoup.find('attribute[name="organization_id"]')
        assert len(org_attr) == 1
        org_val = org_attr[0].find('attributevalue')

        port_attr = samlsoup.find('attribute[name="portal_id"]')
        assert len(port_attr) == 1
        port_val = port_attr[0].find('attributevalue')

        # Assert:
        self.assertTrue(self.login_email in samlresponse)
        self.assertEqual(relaystate,
                         'https://somesite.salesforce.com/SOMETARGETID')
        self.assertEqual(org_val.text, 'SAMPLE_ORG_ID')
        self.assertEqual(port_val.text, 'SAMPLE_PORTAL_ID')
