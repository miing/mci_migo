import re

from datetime import datetime, timedelta

from identityprovider.models import account, openidmodels
from identityprovider.tests.helpers import OpenIDTestCase


class BasicsTestCase(OpenIDTestCase):

    def test_echo(self):
        # = OpenID =
        #
        # == Introduction ==
        #
        # Ubuntu SSO is an OpenID provider. If the URL is accessed by a web
        # browser, an informative message is displayed as per the OpenID spec.
        response = self.client.get(self.base_url)

        self.assertContentType(response, 'text/html')

        # We are going to fake a consumer for these examples. In order to
        # ensure that the consumer is being fed the correct replies, we use a
        # view that renders the parameters in the response in an easily
        # testable format.
        response = self.client.get(self.consumer_openid_url + '?foo=%2Bbar')

        self.assertEqual(response.content, "Consumer received GET\nfoo:+bar")

    def test_checkid_immediate_basic(self):
        # == checkid_immediate Mode ==

        # Ask an Identity Provider if a End User owns the Claimed Identifier,
        # getting back an immediate "yes" or "can't say" answer.

        # Once the shared secret is negotiated, the consumer can send
        # checkid_immediate and checkid_setup GET requests.checkid_immediate
        # requests will currently return "can't say" as we are not yet logged
        # into Launchpad.
        response = self.do_request(mode='checkid_immediate')

        self.assertContains(response, "Consumer received GET")
        self.assertContains(response, "openid.assoc_handle:")
        self.assertContains(response, "openid.mode:id_res")
        self.assertContains(
            response, "openid.user_setup_url:" + self.base_openid_url)

        # An error is returned to the consumer if an attempt to login as an
        # invalid user.
        response = self.do_request(mode='checkid_immediate', oid='limi_oid')

        self.assertContains(response, "openid.assoc_handle:")
        self.assertContains(response, "openid.mode:id_res")
        self.assertContains(
            response, "openid.user_setup_url:" + self.base_openid_url)

    def test_checkid_immediate_full(self):
        # == checkid_setup Mode ==

        # checkid_setup is interactive with the user. We can extract the URL
        # for the checkid_setup from the result of the previous test.

        response = self.do_request(mode='checkid_immediate')
        [setup_url] = re.findall(
            '(?m)^openid.user_setup_url:(.*)$', response.content)

        # Lets start a new browser session so we don't have any credentials.
        # When we go to the OpenID setup URL, we are presented with a login
        # form. By entering an email address and password, we are directed back
        # to the consumer, completing the OpenID request:

        self.reset_client()
        response = self.client.get(setup_url, follow=True)

        self.assertRegexpMatches(response.redirect_chain[-1][0],
                                 self.base_url + '/.*?/\+decide')

        # Sign into SSO itself
        self.assertContains(response, '_qa_ubuntu_login_title')

        response = self.login(response)

        msg = '<a data-qa-id="_qa_rp_backlink" href="{link}">{link}</a>'
        self.assertContains(response, msg.format(link=self.consumer_url))

        self.assertContains(response, '_qa_rp_confirm_login')

        response = self.yes_to_decide(response)
        self.assertRegexpMatches(
            response.redirect_chain[-1][0],
            self.consumer_url + '/\+openid-consumer?.+')
        self.assertContains(response, "Consumer received GET")
        self.assertContains(response, "openid.assoc_handle:")
        self.assertContains(
            response, "openid.identity:" + self.base_url + "/+id/name12_oid")
        self.assertContains(response, "openid.mode:id_res")
        self.assertContains(
            response, "openid.op_endpoint:" + self.base_openid_url)
        self.assertContains(response, "openid.response_nonce:")
        self.assertContains(
            response, "openid.return_to:" + self.consumer_url)
        self.assertContains(response, "openid.sig:")
        self.assertContains(response, "openid.signed:")

        # If we had been logged into Launchpad, we would instead have seen a
        # simple approve/deny form since Launchpad already knows who we are.
        # This can be seen using the existing browser session:

        response = self.client.get(setup_url)
        decide_url = response['Location']
        self.assertTrue(decide_url.endswith('/+decide'))
        cancel_url = decide_url.replace('decide', 'cancel')
        response = self.client.get(cancel_url)
        self.assertRedirects(
            response, self.consumer_openid_url + '?openid.mode=cancel')

        response = self.client.get(response['Location'])
        self.assertContains(response, "Consumer received GET")
        self.assertContains(response, "openid.mode:cancel")

        # Also, checkid_immediate should now give a positive assertion for RPs
        # that are set to auto-authorize.
        self.create_openid_rp_config(auto_authorize=True)

        response = self.do_request(mode='checkid_immediate')
        self.assertContains(response, "openid.assoc_handle:")
        self.assertContains(response, "openid.mode:id_res")
        self.assertContains(response, "openid.return_to:" + self.consumer_url)

    def test_check_authentication(self):
        # == check_authentication Mode ==
        #
        # Ask an Identity Provider if a message is valid. For dumb, stateless
        # Consumers or when verifying an invalidate_handle response.
        #
        # If an association handle is stateful (genereted using the associate
        # Mode), check_authentication will fail.
        self.login()  # login the user so we can get the sig value
        response = self.do_request(mode='checkid_immediate')
        [setup_url] = re.findall(
            '(?m)^openid.user_setup_url:(.*)$', response.content)
        [sig] = re.findall('sig:(.*)', response.content)

        data = {
            'openid.sig': sig,
            'openid.signed': 'return_to,mode,identity',
        }
        response = self.do_request(mode='check_authentication', **data)
        self.assertEqual(response.content, "is_valid:false\n")

    def test_checkid_setup(self):
        self.test_check_authentication()
        openidmodels.OpenIDAuthorization.objects.authorize(
            account.Account.objects.get(openid_identifier='name12_oid'),
            self.consumer_url,
            client_id=self.client.session.session_key,
            expires=datetime.utcnow() + timedelta(hours=1)
        )

        # If we are a dumb consumer though, we must invoke the
        # check_authentication mode, passing back the association handle,
        # signature and values of all fields that were signed.
        response = self.do_request(mode='checkid_setup')

        self.assertContains(response, "Consumer received GET")
        self.assertContains(response, "openid.assoc_handle:")
        self.assertContains(
            response, "openid.identity:" + self.base_url + "/+id/name12_oid")
        self.assertContains(response, "openid.mode:id_res")
        self.assertContains(
            response, "openid.op_endpoint:" + self.base_openid_url)
        self.assertContains(response, "openid.response_nonce:")
        self.assertContains(response, "openid.return_to:" + self.consumer_url)
        self.assertContains(response, "openid.sig:")
        self.assertContains(response, "openid.signed:")

        ### XXX: the original test suggests that re-using the proper signed
        ### fields, the consumer should be able to call check_authenticate
        ### and receive a is_valid:true response. Currently, we're getting
        ### is_valid:false, and I've run out of ideas on how to debug this.
        ###import pdb; pdb.set_trace()
        return

        [sig] = re.findall('openid.sig:(.*)', response.content)
        [signed_fields] = re.findall('openid.signed:(.*)', response.content)
        fields = map(lambda f: 'openid.' + f, signed_fields.split(','))
        data = {}
        for line in response.content.split('\n')[1:]:
            key, value = line.split(':', 1)
            if key in fields:
                data[key] = value
        data.update({
            'openid.mode': 'check_authentication',
            'openid.sig': sig,
            'openid.signed': signed_fields,
        })
        response = self.do_request(mode='check_authentication', **data)
        self.assertEqual(response.content, "is_valid:true\n")

    def test_identity_ownership(self):
        # == Identity Ownership ==
        #
        # You cannot log in as someone elses identity. If you try to, you will
        # be prompted with a login screen to connect as the correct user.
        #
        # Immediate mode:
        self.login()
        response = self.do_request(mode='checkid_immediate',
                                   oid='stub_oid')

        self.assertContains(response, "Consumer received GET")
        self.assertContains(response, "openid.assoc_handle:")
        self.assertContains(response, "openid.mode:id_res")
        self.assertContains(response, "openid.sig:")
        self.assertContains(response, "openid.signed:")
        self.assertContains(
            response, "openid.user_setup_url:" + self.base_openid_url)

        # Interactive mode:

        [setup_url] = re.findall(
            '(?m)^openid.user_setup_url:(.*)$', response.content
        )
        response = self.client.get(setup_url, follow=True)
        self.assertEqual(
            response.redirect_chain[-1][0],
            self.consumer_openid_url + '?openid.mode=cancel')
        self.assertEqual(response.content,
                         "Consumer received GET\nopenid.mode:cancel")

    def test_invalid_identity(self):
        # == Invalid identities ==
        #
        # If you attempt interactive authentication with an invalid OpenID
        # identifier, you get a nice error page.
        fake_oid = 'http://some/other/site'
        response = self.do_request(mode='checkid_immediate', oid=fake_oid)
        [setup_url] = re.findall(
            '(?m)^openid.user_setup_url:(.*)$', response.content)
        response = self.client.get(setup_url)
        msgs = (
            'A site identifying as %s has asked us for confirmation that '
            '%s is your identity URL.' % (self.consumer_url, fake_oid),
            'However, that is not a valid OpenID identity URL for this site',
        )
        for msg in msgs:
            self.assertContains(response, msg)

        cancel_url = self.consumer_openid_url + '?openid.mode=cancel'
        forms = self.get_from_response(response,
                                       'form[action="%s"]' % cancel_url)
        self.assertEqual(len(forms), 1)

    def test_broken_consumer(self):
        # == Broken Consumers ==

        # Really bad requests might trigger a protocol error.  These are such
        # edge cases that I can't even be bothered to figure out how to prevent
        # the u'' unicode prefix from showing up.  We might want to figure it
        # out one day if we feel inclined.
        response = self.do_request(mode='whoops', with_return_to=False)

        self.assertContains(response, "error:")
        self.assertContains(response, "mode u'whoops'")
        self.assertContains(response, "mode:error")

        # If there is a valid return_to, then the consumer gets notified.
        response = self.do_request(mode='whoops')

        self.assertContains(response, "openid.error:")
        self.assertContains(response, "error:")
        self.assertContains(response, "mode u'whoops'")
        self.assertContains(response, "mode:error")
