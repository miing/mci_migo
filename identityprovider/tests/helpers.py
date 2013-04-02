# Copyright 2010-2013 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

import re

from urlparse import parse_qs

from django.contrib.auth.models import User
from django.core.urlresolvers import reverse
from django.test import client
from openid import fetchers
from openid.consumer.consumer import Consumer
from openid.consumer.discover import (
    OPENID_1_0_TYPE,
    OPENID_1_1_TYPE,
    OPENID_2_0_TYPE,
    OPENID_IDP_2_0_TYPE,
    OpenIDServiceEndpoint,
    discover,
    discoverNoYadis,
)
from openid.message import IDENTIFIER_SELECT
from openid.store.memstore import MemoryStore
from pyquery import PyQuery

from identityprovider.const import LAUNCHPAD_TEAMS_NS
from identityprovider.models import AuthToken, OpenIDRPConfig
from identityprovider.models.const import TokenType
from identityprovider.tests import DEFAULT_USER_PASSWORD
from identityprovider.tests.utils import SSOBaseTestCase, patch_settings
from webui.views.consumer import fetchers as webui_fetchers


OPENID_TYPES = [OPENID_1_0_TYPE, OPENID_1_1_TYPE, OPENID_2_0_TYPE]


class DummyFetcher(fetchers.HTTPFetcher):
    """A dummy HTTPFetcher that uses the django test client."""

    def __init__(self, *args, **kwargs):
        self.client = kwargs.pop('client')
        super(DummyFetcher, self).__init__(*args, **kwargs)

    def fetch(self, url, body=None, headers=None):
        kwargs = {}
        if headers is not None:
            for k, v in headers.iteritems():
                kwargs['HTTP_' + k.upper()] = v

        data = {}
        if body is not None:
            data = parse_qs(body)

        response = self.client.get(url, data=data, **kwargs)
        headers = dict((k, response[k]) for k in response._headers)
        result = fetchers.HTTPResponse(
            final_url=url, status=response.status_code,
            headers=headers, body=response.content)

        return result


class FunctionalTestCase(SSOBaseTestCase):

    base_url = 'http://testserver'
    base_openid_url = base_url + '/+openid'
    consumer_url = 'http://launchpad.dev'
    consumer_openid_url = consumer_url + '/+openid-consumer'

    default_email = 'test@canonical.com'
    default_password = DEFAULT_USER_PASSWORD
    new_email = 'new-user@example.com'

    def setUp(self):
        super(FunctionalTestCase, self).setUp()

        p = patch_settings(
            DEBUG=True,
            TESTING=True,
            SSO_ROOT_URL=self.base_url,
            SSO_PROVIDER_URL=self.base_openid_url,
            OPENID_PREAUTHORIZATION_ACL=(
                (self.consumer_url, self.consumer_url),
                (self.base_url, self.base_url),
            ),
            SSO_RESTRICT_RP=False,
        )
        p.start()
        self.addCleanup(p.stop)

        # Create an admin user
        User.objects.create_superuser(
            username='admin', password='Admin007', email='a@a.com')
        # Create a regular user
        self.account = self.factory.make_account(
            email=self.default_email, password=self.default_password)
        self.factory.make_email_for_account(
            email='testing@canonical.com', account=self.account)
        self.claimed_id = (self.base_url + '/+id/' +
                           self.account.openid_identifier)

    def reset_client(self):
        self.client = client.Client()

    def login(self, response=None, email=None, password=None):
        if response is None:
            response = self.client.get(reverse('login'), follow=True)
        if email is None:
            email = self.default_email
        if password is None:
            password = self.default_password

        data = dict(email=email, password=password)
        next_url = self.get_from_response(response,
                                          'input[type="hidden"][name="next"]')
        if len(next_url) == 1:
            data['next'] = next_url[0].get('value')

        try:
            login_url = response.context['login_path']
        except KeyError:
            login_url = None

        if login_url is None:
            login_link = self.get_from_response(response, 'a#login-link')
            self.assertEqual(len(login_link), 1)
            login_url = login_link[0].get('href')

        response = self.client.post(login_url, data=data, follow=True)

        return response

    def logout(self, response):
        logout_link = self.get_from_response(response, 'a#logout-link')
        self.assertEqual(len(logout_link), 1)
        logout_url = logout_link[0].get('href')

        response = self.client.get(logout_url, follow=True)

        return response

    def _get_token(self, token_type, email=None):
        if email is None:
            email = self.new_email
        token = AuthToken.objects.filter(
            email=email, token_type=token_type, date_consumed=None)
        return token.order_by('-date_created')[0].token

    def confirm_link(self, email=None):
        if email is None:
            email = self.new_email
        token = self._get_token(token_type=TokenType.NEWPERSONLESSACCOUNT,
                                email=email)
        return '/confirm-account/%s/%s' % (token, email)

    def recover_link(self, email=None):
        token = self._get_token(token_type=TokenType.PASSWORDRECOVERY,
                                email=email)
        return '/token/%s/' % (token,)

    def new_email_link(self, email=None):
        token = self._get_token(token_type=TokenType.VALIDATEEMAIL,
                                email=email)
        return '/token/%s/' % (token,)

    def get_from_response(self, response, css_selector):
        tree = PyQuery(response.content)
        return tree.find(css_selector)

    def get_attribute_from_response(self, response, css_selector, attribute):
        """Return attribute belonging to first match"""
        elements = self.get_from_response(response, css_selector)
        self.assertIsNotNone(elements[0].get(attribute))
        return elements[0].get(attribute)

    def title_from_response(self, response):
        return self.get_from_response(response, 'head title').text()

    def submit_from_response(self, response):
        buttons = self.get_from_response(response, 'button[type="submit"]')
        self.assertEqual(len(buttons), 1)
        return buttons[0]

    def assertContentType(self, response, expected_content_type):
        content_type = response['content-type']
        if ';' in content_type:
            content_type = content_type.split(';', 1)[0]

        self.assertEqual(content_type, expected_content_type,
                         "Content type %s doesn't match expected %s" %
                         (content_type, expected_content_type))

    def assertRegexpMatches(self, string, regexp):
        if not re.search(regexp, string):
            msg = "Regular expression '%s' does not match '%s'"
            self.fail(msg % (regexp, string))

    def assert_home_page(self, response):
        title = self.title_from_response(response)
        self.assertEqual(title, "%s's details" % self.account.displayname)

    def create_openid_rp_config(self, **extra):
        kwargs = {
            'trust_root': self.consumer_url,
            'displayname': 'Test RP',
            'auto_authorize': False,
        }
        kwargs.update(extra)
        OpenIDRPConfig.objects.filter(trust_root=kwargs['trust_root']).delete()
        return OpenIDRPConfig.objects.create(**kwargs)

    def get_assoc_handle(self):
        # Establish a shared secret between Consumer and Identity Provider.

        # After determining the URL of the OpenID server, the next thing a
        # consumer needs to do is associate with the server and get a shared
        # secret via a POST request.
        data = {
            'openid.mode': 'associate',
            'openid.assoc_type': 'HMAC-SHA1'
        }
        response = self.client.get(self.base_openid_url, data=data)

        self.assertContentType(response, 'text/plain')
        self.assertRegexpMatches(response.content,
                                 'assoc_handle:\{HMAC-SHA1\}\{.*?\}\{.*?\}')
        self.assertRegexpMatches(response.content, 'assoc_type:HMAC-SHA1')
        self.assertRegexpMatches(response.content, 'expires_in:1209.*?')
        self.assertRegexpMatches(response.content, 'mac_key:.*?')

        # Get the association handle, which we will need for later tests.
        [assoc_handle] = re.findall('assoc_handle:(.*)', response.content)
        return assoc_handle

    def do_request(self, mode, oid=None,
                   with_assoc_handle=True, with_return_to=True, **extra):

        data = {'openid.mode': mode, 'openid.trust_root': self.consumer_url}
        if oid is None:
            oid = self.claimed_id
        elif not oid.startswith('http'):
            oid = self.base_url + '/+id/' + oid
        data['openid.identity'] = oid

        if with_return_to:
            data['openid.return_to'] = self.consumer_openid_url

        if with_assoc_handle:
            data['openid.assoc_handle'] = self.get_assoc_handle()

        data.update(extra)
        return self.client.get(self.base_openid_url, data=data, follow=True)


class OpenIDTestCase(FunctionalTestCase):

    def setUp(self):
        super(OpenIDTestCase, self).setUp()
        self.fetcher = DummyFetcher(client=self.client)
        for mod in (fetchers, webui_fetchers):
            default_fetcher = mod.getDefaultFetcher()
            mod.setDefaultFetcher(self.fetcher)
            self.addCleanup(mod.setDefaultFetcher, default_fetcher)

        openid_store = MemoryStore()
        self.consumer = Consumer(session={}, store=openid_store)

    def do_openid_dance(self, claimed_id=None, with_discovery=False,
                        extension=None, teams=None, url_from=None,
                        **kwargs):
        if with_discovery:
            assert claimed_id is not None
            request = self.consumer.begin(claimed_id)
        else:
            if claimed_id is None:
                claimed_id = self.make_identifier_select_endpoint(
                    OPENID_2_0_TYPE)
            else:
                claimed_id = self.make_endpoint(OPENID_2_0_TYPE, claimed_id)
            request = self.consumer.beginWithoutDiscovery(claimed_id)

        if extension:
            request.addExtension(extension)

        if teams:
            request.message.namespaces.addAlias(LAUNCHPAD_TEAMS_NS, 'lp')
            request.addExtensionArg(LAUNCHPAD_TEAMS_NS, 'query_membership',
                                    teams)
        if url_from is None:
            url_from = self.consumer_url
            url_to = self.consumer_openid_url
        else:
            url_to = url_from + '/+openid-consumer'

        redirect = request.redirectURL(url_from, url_to)
        self.assertRegexpMatches(redirect, self.base_url + '/\+openid\?.*?')

        response = self.client.get(redirect, follow=True, **kwargs)

        return response

    def yes_to_decide(self, response, teams=None, **kwargs):
        decide_url = response.redirect_chain[-1][0]
        assert decide_url.endswith('+decide'), (
            'The url %r should end with +decide' % decide_url)
        data = dict(ok=True)
        if teams:
            for t in teams:
                data[t] = True
        data.update(kwargs)

        response = self.client.post(decide_url, data=data, follow=True)

        self.assertRegexpMatches(response.redirect_chain[-1][0],
                                 'http://.*/\+openid-consumer\?.*?')
        return response

    def get_endpoints(self, url='/', yadis=True):
        """Print the OpenID services found through YADIS discovery."""
        if not url.startswith('http'):
            url = self.base_url + url
        if not yadis:
            claimed_id, services = discoverNoYadis(url)
        else:
            claimed_id, services = discover(url)

        endpoints = []
        for s in services:
            endpoints.append({
                'local_id': s.getLocalID(),
                'server_url': s.server_url,
                'supports': [t for t in s.type_uris]
            })

        return {
            'claimed_id': claimed_id,
            'endpoints': endpoints,
        }

    def make_identifier_select_endpoint(self, protocol_uri):
        """Create an endpoint for use in OpenID identifier select mode.

        :arg protocol_uri: The URI for the OpenID protocol version.  This
            should be one of the OPENID_X_Y_TYPE constants.

        If the OpenID 1.x protocol is selected, the endpoint will be
        suitable for use with Launchpad's non-standard identifier select
        workflow.
        """
        msg = "Unexpected protocol URI: %s" % protocol_uri
        assert protocol_uri in OPENID_TYPES, msg

        endpoint = OpenIDServiceEndpoint()
        endpoint.server_url = self.base_openid_url
        if protocol_uri == OPENID_2_0_TYPE:
            endpoint.type_uris = [OPENID_IDP_2_0_TYPE]
        else:
            endpoint.type_uris = [protocol_uri]
            endpoint.claimed_id = IDENTIFIER_SELECT
            endpoint.local_id = IDENTIFIER_SELECT
        return endpoint

    def make_endpoint(self, protocol_uri, claimed_id, local_id=None):
        """Create an endpoint for use with `Consumer.beginWithoutDiscovery`.

        :arg protocol_uri: The URI for the OpenID protocol version.  This
            should be one of the OPENID_X_Y_TYPE constants.
        :arg claimed_id: The claimed identity URL for the endpoint.
        :arg local_id: The OP local identifier for the endpoint.  If this
            argument is not provided, it defaults to claimed_id.
        """
        msg = "Unexpected protocol URI: %s" % protocol_uri
        assert protocol_uri in OPENID_TYPES, msg

        endpoint = OpenIDServiceEndpoint()
        endpoint.type_uris = [protocol_uri]
        endpoint.server_url = self.base_openid_url
        endpoint.claimed_id = claimed_id
        endpoint.local_id = local_id or claimed_id
        return endpoint

    def maybe_fixup_identifier_select_request(self, claimed_id):
        """Fix up an OpenID 1.x identifier select request.

        :arg claimed_id: the expected claimed ID for the response.

        OpenID 1.x does not support identifier select, so responses using
        our non-standard identifier select mode appear to be corrupt.

        This function checks to see if the current request was a 1.x
        identifier select one, and updates the internal state to use the
        given claimed ID if so.
        """
        endpoint = self.consumer.session[self.consumer._token_key]
        if (OPENID_1_0_TYPE in endpoint.type_uris or
                OPENID_1_1_TYPE in endpoint.type_uris):
            assert endpoint.claimed_id == IDENTIFIER_SELECT, (
                "Request did not use identifier select mode")
            endpoint.claimed_id = claimed_id
            endpoint.local_id = claimed_id
        else:
            # For standard identifier select, local_id is None.
            assert endpoint.local_id is None, (
                "Request did not use identifier select mode")

    def complete_from_response(self, response, expected_claimed_id=None):
        """Complete OpenID request based on output of +openid-consumer.

        :arg response: a response from a django test client call.
        :arg expected_claimed_id: the expected claimed ID for the response,
            or None if the request did not use identifier select mode.

        This function parses the body of the +openid-consumer view into a
        set of query arguments representing the OpenID response.

        If the third argument is provided, it will also attempt to fix up
        1.x identifier select requests.
        """
        msg = ('Browser contents does not look like it came from %s' %
               self.consumer_openid_url)
        assert response.content.startswith('Consumer received '), msg
        # Skip the first "Consumer received GET" line
        query = dict(line.split(':', 1)
                     for line in response.content.splitlines()[1:])
        if expected_claimed_id is not None:
            self.maybe_fixup_identifier_select_request(expected_claimed_id)
            # The return_to URL verification for OpenID 1.x requests fails
            # for our non-standard identifier select mode, so disable it.
            self.consumer.consumer._verifyDiscoveryResultsOpenID1 = (
                lambda msg, endpoint: endpoint)

        url = response.redirect_chain[-1][0]
        response = self.consumer.complete(query, url)

        if expected_claimed_id is not None:
            del self.consumer.consumer._verifyDiscoveryResultsOpenID1
        return response
