# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from openid.consumer.consumer import SuccessResponse
from openid.consumer.discover import OpenIDServiceEndpoint
from openid.message import IDENTIFIER_SELECT

from identityprovider.teams import (
    TeamsNamespaceError,
    TeamsRequest,
    TeamsResponse,
    supportsTeams,
    getTeamsNS,
    ns_uri,
)
from identityprovider.tests.utils import SSOBaseTestCase
from identityprovider.views import server


class TeamsTestCase(SSOBaseTestCase):

    def test_supportsTeams(self):
        endpoint = OpenIDServiceEndpoint()
        endpoint.type_uris.append(ns_uri)
        r = supportsTeams(endpoint)
        self.assertTrue(r)

    def test_not_supportsTeams(self):
        endpoint = OpenIDServiceEndpoint()
        r = supportsTeams(endpoint)
        self.assertFalse(r)


class GetTeamsNSTestCase(SSOBaseTestCase):
    def setUp(self):
        super(GetTeamsNSTestCase, self).setUp()

        request = {'openid.mode': 'checkid_setup',
                   'openid.trust_root': 'http://localhost/',
                   'openid.return_to': 'http://localhost/',
                   'openid.identity': IDENTIFIER_SELECT}
        openid_server = server._get_openid_server()
        self.orequest = openid_server.decodeRequest(request)

    def test_getTeamsNS(self):
        message = self.orequest.message
        self.assertEqual(message.namespaces.getAlias(ns_uri), None)
        uri = getTeamsNS(message)
        self.assertEqual(uri, ns_uri)
        self.assertEqual(message.namespaces.getAlias(ns_uri), 'lp')

    def test_getTeamsNS_alias_already_exists(self):
        message = self.orequest.message
        message.namespaces.addAlias('http://localhost/', 'lp')
        self.assertEqual(message.namespaces.getAlias(ns_uri), None)
        self.assertRaises(TeamsNamespaceError, getTeamsNS, message)


class TeamsRequestTestCase(SSOBaseTestCase):
    def setUp(self):
        super(TeamsRequestTestCase, self).setUp()

        self.req = TeamsRequest(
            query_membership=['canonical-identity-provider'])

    def test_init(self):
        req = TeamsRequest()
        self.assertEqual(req.query_membership, [])
        self.assertEqual(req.ns_uri, ns_uri)

        self.assertEqual(self.req.query_membership,
                         ['canonical-identity-provider'])

        self.assertRaises(TypeError, TeamsRequest,
                          query_membership='canonical-identity-provider')

    def test_fromOpenIDRequest(self):
        request = {'openid.mode': 'checkid_setup',
                   'openid.trust_root': 'http://localhost/',
                   'openid.return_to': 'http://localhost/',
                   'openid.identity': IDENTIFIER_SELECT}
        openid_server = server._get_openid_server()
        orequest = openid_server.decodeRequest(request)
        req = TeamsRequest.fromOpenIDRequest(orequest)
        self.assertEqual(req.query_membership, [])
        self.assertEqual(req.ns_uri, ns_uri)

    def test_fromOpenIDRequest_with_query_membership(self):
        request = {'openid.mode': 'checkid_setup',
                   'openid.trust_root': 'http://localhost/',
                   'openid.return_to': 'http://localhost/',
                   'openid.identity': IDENTIFIER_SELECT,
                   'openid.lp.query_membership': 'canonical-identity-provider'}
        openid_server = server._get_openid_server()
        orequest = openid_server.decodeRequest(request)
        req = TeamsRequest.fromOpenIDRequest(orequest)
        self.assertEqual(req.query_membership, ['canonical-identity-provider'])
        self.assertEqual(req.ns_uri, ns_uri)

    def test_parseExtensionArgs_no_strict(self):
        req = TeamsRequest()
        req.parseExtensionArgs(
            {'query_membership':
             'canonical-identity-provider,canonical-identity-provider'},
            strict=False)
        self.assertEqual(req.query_membership, ['canonical-identity-provider'])

    def test_parseExtensionArgs_strict(self):
        req = TeamsRequest()
        self.assertRaises(
            ValueError, req.parseExtensionArgs,
            {'query_membership':
             'canonical-identity-provider,canonical-identity-provider'},
            strict=True)

    def test_allRequestedTeams(self):
        self.assertEqual(self.req.allRequestedTeams(),
                         ['canonical-identity-provider'])

    def test_not_wereTeamsRequested(self):
        req = TeamsRequest()
        self.assertFalse(req.wereTeamsRequested())

    def test_wereTeamsRequested(self):
        self.assertTrue(self.req.wereTeamsRequested())

    def test_contains(self):
        self.assertTrue('canonical-identity-provider' in self.req)
        self.assertFalse('other-team' in self.req)

    def test_getExtensionArgs(self):
        expected = {'query_membership': 'canonical-identity-provider'}
        self.assertEqual(self.req.getExtensionArgs(), expected)

        teams = ['canonical-identity-provider', 'other-team']
        expected = {'query_membership': ','.join(teams)}
        req = TeamsRequest(query_membership=teams)
        self.assertEqual(req.getExtensionArgs(), expected)


class TeamsResponseTestCase(SSOBaseTestCase):

    def test_init(self):
        resp = TeamsResponse()
        self.assertEqual(resp.is_member, [])
        self.assertEqual(resp.ns_uri, ns_uri)

        resp = TeamsResponse(is_member=['canonical-identity-provider'])
        self.assertEqual(resp.is_member, ['canonical-identity-provider'])

    def test_addTeam(self):
        resp = TeamsResponse()
        self.assertEqual(resp.is_member, [])
        resp.addTeam('canonical-identity-provider')
        self.assertEqual(resp.is_member, ['canonical-identity-provider'])

    def test_extractResponse(self):
        req = TeamsRequest()
        is_member_str = 'canonical-identity-provider'
        resp = TeamsResponse.extractResponse(req, is_member_str)
        self.assertEqual(resp.ns_uri, req.ns_uri)
        self.assertEqual(resp.is_member, ['canonical-identity-provider'])

    def test_fromSuccessResponse_signed_present(self):
        request = {'openid.mode': 'checkid_setup',
                   'openid.trust_root': 'http://localhost/',
                   'openid.return_to': 'http://localhost/',
                   'openid.identity': IDENTIFIER_SELECT,
                   'openid.lp.is_member': 'canonical-identity-provider'}
        openid_server = server._get_openid_server()
        orequest = openid_server.decodeRequest(request)
        signed_fields = ['openid.lp.is_member']
        success_resp = SuccessResponse(orequest, orequest.message,
                                       signed_fields=signed_fields)
        resp = TeamsResponse.fromSuccessResponse(success_resp)
        self.assertEqual(resp.is_member, ['canonical-identity-provider'])

    def test_fromSuccessResponse_no_signed(self):
        request = {'openid.mode': 'checkid_setup',
                   'openid.trust_root': 'http://localhost/',
                   'openid.return_to': 'http://localhost/',
                   'openid.identity': IDENTIFIER_SELECT}
        openid_server = server._get_openid_server()
        orequest = openid_server.decodeRequest(request)
        success_resp = SuccessResponse(orequest, orequest.message)
        resp = TeamsResponse.fromSuccessResponse(success_resp)
        self.assertEqual(resp.is_member, [])

    def test_fromSuccessResponse_all(self):
        request = {'openid.mode': 'checkid_setup',
                   'openid.trust_root': 'http://localhost/',
                   'openid.return_to': 'http://localhost/',
                   'openid.identity': IDENTIFIER_SELECT,
                   'openid.lp.is_member': 'canonical-identity-provider'}
        openid_server = server._get_openid_server()
        orequest = openid_server.decodeRequest(request)
        success_resp = SuccessResponse(orequest, orequest.message)
        resp = TeamsResponse.fromSuccessResponse(success_resp, False)
        self.assertEqual(resp.is_member, ['canonical-identity-provider'])

    def test_getExtensionArgs(self):
        expected = {'is_member': 'canonical-identity-provider'}
        req = TeamsResponse(is_member=['canonical-identity-provider'])
        self.assertEqual(req.getExtensionArgs(), expected)

        teams = ['canonical-identity-provider', 'other-team']
        expected = {'is_member': ','.join(teams)}
        req = TeamsResponse(is_member=teams)
        self.assertEqual(req.getExtensionArgs(), expected)
