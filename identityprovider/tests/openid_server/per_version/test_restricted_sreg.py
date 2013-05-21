from openid.extensions.sreg import SRegRequest, SRegResponse

from identityprovider.tests.helpers import OpenIDTestCase


class RestrictedSregTestCase(OpenIDTestCase):

    def setUp(self):
        super(RestrictedSregTestCase, self).setUp()

        t = self.factory.make_team('ubuntu-team')
        self.factory.add_account_to_team(self.account, t)

        # We will perform an OpenID authentication request asking for a few
        # user details:
        self.required = ['email', 'country']
        self.optional = ['fullname', 'nickname']

    def initial_dance(self, with_login=True):
        extension = SRegRequest(required=self.required, optional=self.optional)
        response = self.do_openid_dance(self.claimed_id, extension=extension)

        if with_login:  # log in
            response = self.login(response)

        return response

    def test_required_fields_checked(self):
        # = Restricted OpenID Simple Registration Extension support =

        # The Launchpad OpenID server has restricted support for the OpenID
        # Simple Registration Extension.  It will only provide a full set of
        # registration details to certain known trust roots.  The user's
        # launchpad username is share with all roots.

        # This is done in order to share the user details among the various
        # Canonical/Ubuntu sites participating in single sign-on.  The user's
        # nickname is published to every site, which is useful things like
        # weblog comments.

        # == Behaviour for unknown trust roots ==

        # If a relying party attempts to request user details via the
        # openid.sreg extension and Launchpad does not have a particular policy
        # configured, then only the user's approved fields are returned in the
        # response.

        response = self.initial_dance()
        # authorize data
        # required fields are checked by default. don't authorize anything
        fields = self.get_from_response(response, 'input[type="checkbox"]')
        self.assertEqual(len(fields), 3)
        for f in fields:
            self.assertFalse(f.get('disabled'))
            self.assertEqual(f.get('checked') == 'checked',
                             f.get('name') in self.required)

        # do not send any field in the post
        response = self.yes_to_decide(response)

        # We have authenticated successfully:
        info = self.complete_from_response(response)

        self.assertEqual(info.status, 'success')
        self.assertEqual(info.endpoint.claimed_id, self.claimed_id)

        # But no fields are returned:

        sreg_response = SRegResponse.fromSuccessResponse(info)

        self.assertEqual(sreg_response, None)

        # If we attempt to authenticate again, we will be prompted to
        # confirm which fields we want to provide to the RP again,
        # but the defaults will be what we provided last time:

        # No log in needed this time, we're directed straight to the confirm
        # screen.  Check that email is *not* selected by default this time:
        response = self.initial_dance(with_login=False)
        fields = self.get_from_response(response, 'input[type="checkbox"]')
        self.assertEqual(len(fields), 3)
        for f in fields:
            self.assertFalse(f.get('disabled'))
            self.assertFalse(f.get('checked'))

    def test_known_trust_root(self):
        # == Behaviour for known trust roots ==

        # If we create a Relying Party configuration for the trust root, things
        # play out a bit differently:

        allowed_user_attribs = ','.join(['fullname', 'nickname',
                                         'email', 'timezone'])
        self.create_openid_rp_config(
            trust_root=self.consumer_url,
            allowed_user_attribs=allowed_user_attribs)

        # Now begin another identical OpenID authentication request:
        response = self.initial_dance()
        # authorize data
        # required fields cannot be unchecked.
        fields = self.get_from_response(response, 'input[type="checkbox"]')
        self.assertEqual(len(fields), 3)
        for f in fields:
            self.assertEqual(f.get('disabled') == 'disabled',
                             f.get('name') in self.required)
            self.assertTrue(f.get('checked'))

        # authorize nickname
        # unauthorize fullname (checked by default)
        response = self.yes_to_decide(response, nickname=True)

        # Again, the authentication request is successful:
        info = self.complete_from_response(response)

        self.assertEqual(info.status, 'success')
        self.assertEqual(info.endpoint.claimed_id, self.claimed_id)

        # But now we have some user details.
        sreg_response = SRegResponse.fromSuccessResponse(info)
        self.assertEqual(list(sorted(sreg_response.items())),
                         [('email', self.account.preferredemail.email),
                          ('nickname', self.account.person.name)])

    def test_known_trust_roots_with_auto_authorize(self):
        # == Behaviour for known trust roots with auto_authorize ==

        # enable auto-authorize for the rpconfig
        allowed_user_attribs = ','.join(['fullname', 'email', 'timezone'])
        self.create_openid_rp_config(
            trust_root=self.consumer_url,
            allowed_user_attribs=allowed_user_attribs, auto_authorize=True)
        # Now begin another identical OpenID authentication request:
        response = self.initial_dance()

        # Again, the authentication request is successful:
        info = self.complete_from_response(response)

        self.assertEqual(info.status, 'success')
        self.assertEqual(info.endpoint.claimed_id, self.claimed_id)

        # Again, we have some user details, but this time, the optional
        # sreg fields are also included automatically.

        sreg_response = SRegResponse.fromSuccessResponse(info)

        self.assertEqual(list(sorted(sreg_response.items())),
                         [('email', self.account.preferredemail.email),
                          ('fullname', self.account.displayname)])
