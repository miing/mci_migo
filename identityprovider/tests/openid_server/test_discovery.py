from openid.yadis.discover import DiscoveryFailure

from identityprovider.models import LPOpenIdIdentifier
from identityprovider.models.const import (
    AccountCreationRationale,
    AccountStatus,
)
from identityprovider.tests.helpers import OpenIDTestCase


class DiscoveryTestCase(OpenIDTestCase):

    def test_by_openid(self):
        # = OpenID Discovery =
        #
        # SSO provides a number of pages that can be used as OpenID URLs.
        # The OpenID discovery process can be run on them to discover the
        # endpoints.

        # == Persistent User Identity URLs ==
        # SSO assigns a persistent identifier to each user:
        endpoints = self.get_endpoints(
            '/+id/' + self.account.openid_identifier)

        self.assertEqual(endpoints, {
            'claimed_id': self.claimed_id,
            'endpoints': [{
                'local_id': self.claimed_id,
                'server_url': self.base_openid_url,
                'supports': ['http://specs.openid.net/auth/2.0/signon']
            }, {
                'local_id': self.claimed_id,
                'server_url': self.base_openid_url,
                'supports': ['http://openid.net/signon/1.1']
            }, {
                'local_id': self.claimed_id,
                'server_url': self.base_openid_url,
                'supports': ['http://openid.net/signon/1.0']
            }]
        })

    def test_on_root(self):
        # == OP Identifier Discovery ==
        #
        # It is also possible to run discovery on the root directory as an OP
        # identifier.  This allows any Launchpad user to log in by entering
        # this URL.
        endpoints = self.get_endpoints()

        self.assertEqual(endpoints, {
            'claimed_id': self.base_url + '/',
            'endpoints': [{
                'local_id': None,
                'server_url': self.base_openid_url,
                'supports': [
                    'http://specs.openid.net/auth/2.0/server',
                    'http://openid.net/srv/ax/1.0',
                    'http://openid.net/extensions/sreg/1.1',
                    'http://ns.launchpad.net/2007/openid-teams',
                ],
            }],
        })

    def test_invalid_openid(self):
        # == Invalid Persistent Identifiers ==
        #
        # Discovery is not possible on non-existent persistent identifiers:
        response = self.client.get('/+id/no-such-id')
        self.assertContains(response, 'No Account matches the given query.',
                            status_code=404)

        self.assertRaises(DiscoveryFailure,
                          self.get_endpoints, '/+id/no-such-id')

    def test_invalid_user(self):
        # == No OpenID for Invalid Users ==
        #
        # People who are not valid Launchpad users do not have OpenID
        # Identifiers:
        person_name = 'foo'
        account = self.factory.make_account(
            creation_rationale=AccountCreationRationale.POFILEIMPORT,
            status=AccountStatus.NOACCOUNT,
        )
        person = self.factory.make_person(name=person_name, account=account)
        LPOpenIdIdentifier.objects.filter(
            identifier=account.openid_identifier,
            lp_account=account.id).delete()

        assert account.person is None
        assert person.account is None
        endpoints = self.get_endpoints('/~' + person_name)

        self.assertEqual(endpoints, {
            'claimed_id': self.base_url + '/~' + person_name,
            'endpoints': []
        })
