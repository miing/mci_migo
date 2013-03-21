# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from identityprovider.tests.utils import SSOBaseTestCase


class XRDSTest(SSOBaseTestCase):

    fixtures = ["test"]

    def test_id_html(self):
        r = self.client.get('/+id/mark_oid')
        self.assertTrue(
            '<html xmlns="http://www.w3.org/1999/xhtml">' in r.content)
        self.assertEqual(r['Content-Type'], 'text/html; charset=utf-8')

    def test_id_html_with_inactive_account(self):
        r = self.client.get('/+id/matsubara_oid')
        self.assertEqual(r.status_code, 404)

    def test_id_accept_xrds(self):
        r = self.client.get('/+id/mark_oid',
                            HTTP_ACCEPT='application/xrds+xml')
        self.assertTrue(r.content.startswith('<?xml version="1.0"?>'))
        self.assertEqual(r['Content-Type'], 'application/xrds+xml')

    def test_id_accept_xrds_with_inactive_account(self):
        r = self.client.get('/+id/matsubara_oid',
                            HTTP_ACCEPT='application/xrds+xml')
        self.assertEqual(r.status_code, 404)

    def test_default_discovery_response(self):
        r = self.client.get('/+openid', HTTP_ACCEPT='application/xrds+xml')
        self.assertTrue(r.has_header('X-XRDS-Location'))
