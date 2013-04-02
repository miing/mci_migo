# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from django.core.urlresolvers import reverse
from identityprovider.tests.utils import SSOBaseTestCase


class XRDSTest(SSOBaseTestCase):

    openid_identifier = 'mark_oid'
    url = reverse('server-identity', kwargs=dict(identifier='mark_oid'))

    def setUp(self):
        super(XRDSTest, self).setUp()
        self.account = self.factory.make_account(
            openid_identifier=self.openid_identifier)

    def test_id_html(self):
        r = self.client.get(self.url)
        self.assertContains(
            r, '<html xmlns="http://www.w3.org/1999/xhtml">')
        self.assertEqual(r['Content-Type'], 'text/html; charset=utf-8')

    def test_id_html_with_inactive_account(self):
        self.account.suspend()
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, 404)

    def test_id_accept_xrds(self):
        r = self.client.get(self.url,
                            HTTP_ACCEPT='application/xrds+xml')
        self.assertTrue(r.content.startswith('<?xml version="1.0"?>'))
        self.assertEqual(r['Content-Type'], 'application/xrds+xml')

    def test_id_accept_xrds_with_inactive_account(self):
        self.account.suspend()
        r = self.client.get(self.url,
                            HTTP_ACCEPT='application/xrds+xml')
        self.assertEqual(r.status_code, 404)

    def test_default_discovery_response(self):
        r = self.client.get(reverse('server-openid'),
                            HTTP_ACCEPT='application/xrds+xml')
        self.assertTrue(r.has_header('X-XRDS-Location'))
