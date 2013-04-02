from identityprovider.tests.helpers import OpenIDTestCase


class DelegatedIdentityTestCase(OpenIDTestCase):

    def assertSupports(self, data, expected_supports):
        supports = [e['supports'] for e in data['endpoints']]

        self.assertEqual(supports, expected_supports)

    def assertEndpointData(self, data, expected_local_id, expected_server_url):
        for endpoint in data['endpoints']:
            self.assertEqual(endpoint['local_id'], expected_local_id)
            self.assertEqual(endpoint['server_url'], expected_server_url)

    def test_endpoints(self):
        # = Launchpad Delegated Identity =
        #
        # The Launchpad profile page acts as an OpenID identifier through
        # delegation.
        # The profile page delegates to the underlying Single Sign On
        # identifier:
        self.factory.make_person(account=self.account)
        account_id = '/~' + self.account.person.name
        data = self.get_endpoints(account_id)
        self.assertEqual(data['claimed_id'], self.base_url + account_id)
        self.assertEndpointData(data, self.claimed_id, self.base_openid_url)
        self.assertSupports(data, [
            ["http://specs.openid.net/auth/2.0/signon"],
            ["http://openid.net/signon/1.1"],
            ["http://openid.net/signon/1.0"]
        ])

        # In case the client doesn't support YADIS discovery, the profile page
        # also includes <link> discovery:

        data = self.get_endpoints(account_id, yadis=False)

        self.assertEqual(data['claimed_id'], self.base_url + account_id)
        self.assertEndpointData(data, self.claimed_id, self.base_openid_url)
        self.assertSupports(data, [["http://specs.openid.net/auth/2.0/signon"],
                                   ["http://openid.net/signon/1.1"]])

    def test_login(self):
        # == Logging in ==
        response = self.do_openid_dance(self.claimed_id, with_discovery=True)
        response = self.login(response)
        response = self.yes_to_decide(response)
        info = self.complete_from_response(response)

        self.assertEqual(info.status, 'success')
        self.assertEqual(info.endpoint.claimed_id, self.claimed_id)
