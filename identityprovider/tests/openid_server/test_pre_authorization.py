from urllib import urlencode

from identityprovider.tests.helpers import OpenIDTestCase


class PreAuthorizationTestCase(OpenIDTestCase):

    def test(self):
        # = Pre-authorized consumers =

        # In some cases we want consumers to be pre-authorized so that the
        # authorization step of the protocol is skipped.  This is the case for
        # canonical's training site: we want the canonical shop to
        # pre-authorize the training site when a user buys some sort of
        # training.

        # To do so the shop has to craft a link which takes the user to the
        # training site through Launchpad.  This is what the link looks like:

        # https://openid.launchpad.net/+pre-authorize-rp? \
        # trust_root=..&callback=...

        # Where the value of trust_root should be the root URL of the consumer
        # to be pre-authorized and callback is the URL to which the user will
        # be redirected after the consumer is pre-authorized.

        # As an example we'll pre-authorize our own OpenID consumer:

        # First, some setup to ensure old data doesn't mess with the results
        data = {
            'trust_root': self.base_url,
            'callback': self.base_url + '/+edit'
        }
        response = self.client.get(
            '/+pre-authorize-rp', data=data, HTTP_REFERER=self.base_url,
            follow=True)

        # Since the user is not logged in, he'll have to login first.
        self.assertRegexpMatches(response.redirect_chain[-1][0],
                                 self.base_url + '/\+login.*?')
        next_button = self.get_from_response(
            response, 'input[type="hidden"][name="next"]')
        self.assertEqual(len(next_button), 1)
        expected = '/+pre-authorize-rp?' + urlencode(data)
        self.assertEqual(next_button[0].get('value'), expected)

        response = self.login(response)  # handles next automatically
        # Now he's redirected to the callback page and the RP has been
        # pre-authorized.
        self.assertEqual(response.redirect_chain[-1][0],
                         self.base_url + '/+edit')

        # The authentication process is started by the relying party issuing a
        # checkid_setup request, sending the user to Launchpad.
        response = self.do_openid_dance()
        response = self.yes_to_decide(response)

        # The user (test) was already logged into Launchpad, so at this point,
        # instead of being presented with a form asking if they want to
        # authenticate to the relying party, they are sent directly to the RP.
        self.assertRegexpMatches(response.redirect_chain[-1][0],
                                 self.consumer_url + '/\+openid-consumer\?.*?')

        # If the HTTP referrer and the trust_root are not in our config's
        # openid_preauthorization_acl, we will not pre-authorize.
        self.client.logout()
        self.login()

        data = {
            'trust_root': 'http://blueprints.testserver/',
            'callback': self.base_url + '/+edit'
        }
        response = self.client.get('/+pre-authorize-rp', data=data)
        self.assertEqual(response.status_code, 400)

        response = self.do_openid_dance(
            url_from='http://blueprints.testserver/')
        title = self.title_from_response(response)
        self.assertEqual(
            title, 'Authenticate to http://blueprints.testserver/')

        response = self.logout(response)
        response = self.login(response)
        data = {
            'trust_root': 'http://example.com',
            'callback': self.consumer_url + '/people/+me'
        }
        response = self.client.get('/+pre-authorize-rp', data=data,
                                   follow=True)
        self.assertEqual(response.status_code, 400)

        response = self.do_openid_dance(url_from='http://example.com')
        title = self.title_from_response(response)
        self.assertEqual(title, 'Authenticate to http://example.com')

        data = {
            'trust_root': 'http://example.com/'
        }
        response = self.client.get('/+pre-authorize-rp', data=data)
        self.assertEqual(response.status_code, 400)

        response = self.do_openid_dance(url_from='http://example.com/')
        title = self.title_from_response(response)
        self.assertEqual(title, 'Authenticate to http://example.com/')
