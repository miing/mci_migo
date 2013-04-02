# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

import base64
from datetime import datetime, timedelta
from time import time

from django.test.client import RequestFactory
from gargoyle.testutils import switches
from mock import patch
from openid.association import Association
from openid.store.nonce import SKEW

from identityprovider.models.account import Account
from identityprovider.models.openidmodels import (
    DjangoOpenIDStore,
    OpenIDAssociation,
    OpenIDAuthorization,
    OpenIDNonce,
    OpenIDRPConfig,
    OpenIDRPSummary,
)
from identityprovider.tests.utils import (
    SSOBaseTestCase,
    patch_settings,
)
from identityprovider.readonly import ReadOnlyManager


class DjangoOpenIDStoreTestCase(SSOBaseTestCase):

    def setUp(self):
        super(DjangoOpenIDStoreTestCase, self).setUp()
        self.server_url = 'http://server.example.com'
        self.store = DjangoOpenIDStore()
        self.assoc, _ = OpenIDAssociation.objects.get_or_create(
            server_url=self.server_url,
            handle="handle", secret="secret".encode("base64"),
            issued=time(), lifetime=1000, assoc_type='HMAC-SHA1')

    def test_store_association_when_association_already_exists(self):
        association = Association("handle", "secret", 2, 2, 'HMAC-SHA1')

        self.store.storeAssociation(self.server_url, association)
        openid_association = OpenIDAssociation.objects.get(
            server_url=self.server_url, handle="handle")

        self.assertEqual(openid_association.issued, 2)

    def test_get_association_with_handle_none(self):
        association = self.store.getAssociation(self.server_url)

        self.assertEqual(association.handle, "handle")

    def test_get_association_when_lifetime_is_zero(self):
        openid_association = OpenIDAssociation.objects.get(
            server_url=self.server_url, handle="handle")
        openid_association.lifetime = 0
        openid_association.save()

        association = self.store.getAssociation(self.server_url)

        self.assertTrue(association is None)

    def test_use_nonce_when_expired(self):
        self.assertFalse(
            self.store.useNonce("url", time() + SKEW + 100, "salt"))

    def test_use_nonce_when_nonce_exists(self):
        OpenIDNonce.objects.create(
            server_url="http://example.com", timestamp=time(), salt="salt")

        self.assertFalse(
            self.store.useNonce("http://example.com", time(), "salt"))

    def test_use_nonce_when_nonce_does_not_exist(self):
        self.assertTrue(
            self.store.useNonce("http://example.com", time(), "salt"))
        OpenIDNonce.objects.get(
            server_url="http://example.com", salt="salt").delete()

    def test_getAssociation_not_existing(self):
        OpenIDAssociation.objects.filter(server_url=self.server_url).delete()
        assoc = self.store.getAssociation(self.server_url)
        self.assertEqual(assoc, None)

    def test_getAssociation_existing_no_handle(self):
        expected = Association(
            self.assoc.handle, base64.b64decode(str(self.assoc.secret)),
            int(self.assoc.issued), self.assoc.lifetime, self.assoc.assoc_type)
        assoc = self.store.getAssociation(self.server_url)
        self.assertEqual(assoc, expected)

    def test_getAssociation_expired(self):
        # make sure the association has expired
        self.assoc.lifetime = 0
        self.assoc.save()

        assoc = self.store.getAssociation(self.server_url)
        self.assertEqual(assoc, None)
        assocs = OpenIDAssociation.objects.filter(server_url=self.server_url)
        self.assertEqual(assocs.count(), 0)

    def test_getAssociation_existing_same_handle(self):
        expected = Association(
            self.assoc.handle, base64.b64decode(str(self.assoc.secret)),
            int(self.assoc.issued), self.assoc.lifetime, self.assoc.assoc_type)
        assoc = self.store.getAssociation(self.server_url, 'handle')
        self.assertEqual(assoc, expected)

    def test_getAssociation_existing_different_handle(self):
        assoc = self.store.getAssociation(self.server_url, 'otherhandle')
        self.assertEqual(assoc, None)

    def test_cleanupNonce(self):
        OpenIDNonce.objects.create(server_url=self.server_url, timestamp=0,
                                   salt='')

        self.assertEqual(OpenIDNonce.objects.all().count(), 1)
        self.store.cleanupNonce()
        self.assertEqual(OpenIDNonce.objects.all().count(), 0)

    def test_cleanupAssociations(self):
        self.assoc.lifetime = 0
        self.assoc.save()

        self.assertEqual(OpenIDAssociation.objects.all().count(), 1)
        self.store.cleanupAssociations()
        self.assertEqual(OpenIDAssociation.objects.all().count(), 0)


class OpenIDRPConfigTestCase(SSOBaseTestCase):

    def setUp(self):
        super(OpenIDRPConfigTestCase, self).setUp()
        self.rp_config = OpenIDRPConfig()

    def test_logo_url_property_when_logo_is_none(self):
        self.rp_config.logo = None

        self.assertTrue(self.rp_config.logo_url is None)

    def test_logo_url_property_when_logo_is_relative(self):
        with patch_settings(MEDIA_URL='http://our_sso_server/media/'):
            self.rp_config.logo = 'test.png'
            self.assertEqual(self.rp_config.logo_url,
                             'http://our_sso_server/media/test.png')

    def test_logo_url_property_when_logo_is_absolute(self):
        with patch_settings(MEDIA_URL='http://our_sso_server/media/'):
            external_logo_url = 'http://www.consumer/logo.png'
            self.rp_config.logo = external_logo_url
            self.assertEqual(self.rp_config.logo_url, external_logo_url)

    def test_unicode(self):
        self.rp_config.displayname = 'MyOpenIDRPConfig'
        self.rp_config.save()
        self.assertEqual(unicode(self.rp_config), u'MyOpenIDRPConfig')

    @switches(TWOFACTOR=False)
    def test_twofactor_required_twofactor_not_enabled(self):
        request = RequestFactory().get('/')
        self.assertFalse(self.rp_config.twofactor_required(request))

    @switches(TWOFACTOR=True)
    def test_twofactor_required_flag_is_null(self):
        self.rp_config.require_two_factor = True
        self.rp_config.flag_twofactor = None
        request = RequestFactory().get('/')
        self.assertTrue(self.rp_config.twofactor_required(request))

    @switches(TWOFACTOR=True)
    def test_twofactor_required_no_flag(self):
        self.rp_config.require_two_factor = True
        self.rp_config.flag_twofactor = ''
        request = RequestFactory().get('/')
        self.assertTrue(self.rp_config.twofactor_required(request))

    @switches(TWOFACTOR=True)
    def test_twofactor_required_with_flag(self):
        self.rp_config.flag_twofactor = 'FOO'
        request = RequestFactory().get('/')
        with switches(FOO=True):
            self.assertTrue(self.rp_config.twofactor_required(request))
        with switches(FOO=False):
            self.assertFalse(self.rp_config.twofactor_required(request))


class OpenIDAssociationTestCase(SSOBaseTestCase):

    def setUp(self):
        super(OpenIDAssociationTestCase, self).setUp()
        for i in xrange(5):
            OpenIDAssociation.objects.create(
                server_url='http://test.com',
                handle='handle%s' % i,
                secret=('secret%s' % i).encode('base64'),
                issued=time(), lifetime=1000, assoc_type='HMAC-SHA1')

    def test_create_association(self):
        # If this creation doesn't fail then our primary key is right,
        # as we've already got several associations with the same
        # trust root.
        OpenIDAssociation.objects.create(
            server_url="http://test.com",
            handle="handle", secret="secret".encode("base64"),
            issued=time(), lifetime=1000, assoc_type='HMAC-SHA1')


class OpenIDAuthorizationTestCase(SSOBaseTestCase):

    fixtures = ["test"]

    def setUp(self):
        super(OpenIDAuthorizationTestCase, self).setUp()
        self.account = Account.objects.get_by_email('test@canonical.com')
        self.trust_root = 'http://foo.bar.baz'
        self.expires = datetime.utcnow() + timedelta(1)

    def create_auth(self):
        return OpenIDAuthorization.objects.create(
            account=self.account, client_id=None, date_expires=self.expires,
            trust_root=self.trust_root)

    def test_authorize_when_readonly(self):
        rm = ReadOnlyManager()
        rm.set_readonly()
        self.addCleanup(rm.clear_readonly)

        expires = datetime.utcnow()
        OpenIDAuthorization.objects.authorize(self.account, self.trust_root,
                                              expires)
        self.assertRaises(
            OpenIDAuthorization.DoesNotExist,
            OpenIDAuthorization.objects.get, account=self.account,
            client_id=None, trust_root=self.trust_root)

    @patch('identityprovider.models.openidmodels.datetime')
    def test_authorize_expires(self, mock_datetime):
        now = datetime.utcnow()
        mock_datetime.utcnow.return_value = now

        OpenIDAuthorization.objects.authorize(self.account, self.trust_root)

        auth = OpenIDAuthorization.objects.get(
            account=self.account, client_id=None, trust_root=self.trust_root)
        self.assertEqual(auth.date_expires, now)

    @patch('identityprovider.models.openidmodels.datetime')
    def test_authorize_existing(self, mock_datetime):
        now = datetime.utcnow()
        mock_datetime.utcnow.return_value = now
        auth1 = self.create_auth()
        OpenIDAuthorization.objects.authorize(self.account, self.trust_root)
        auth2 = OpenIDAuthorization.objects.get(pk=auth1.id)
        self.assertEqual(auth2.date_expires, now)

    @patch('identityprovider.models.openidmodels.datetime')
    def test_authorize_not_existing(self, mock_datetime):
        now = datetime.utcnow()
        mock_datetime.utcnow.return_value = now
        OpenIDAuthorization.objects.authorize(self.account, self.trust_root,
                                              None)
        auth = OpenIDAuthorization.objects.get(
            account=self.account, client_id=None, trust_root=self.trust_root)
        self.assertEqual(auth.date_expires, now)

    def test_is_authorized_generic(self):
        self.create_auth()
        self.assertTrue(OpenIDAuthorization.objects.is_authorized(
            self.account, self.trust_root, 'client'))

    def test_is_authorized_client_id(self):
        self.assertFalse(OpenIDAuthorization.objects.is_authorized(
            self.account, self.trust_root, 'client'))
        OpenIDAuthorization.objects.authorize(
            self.account, self.trust_root,
            expires=self.expires, client_id='client')
        self.assertTrue(OpenIDAuthorization.objects.is_authorized(
            self.account, self.trust_root, 'client'))

    def test_is_not_authorized(self):
        self.assertFalse(OpenIDAuthorization.objects.is_authorized(
            self.account, self.trust_root, 'client'))


class OpenIDRPSummaryTestCase(SSOBaseTestCase):

    fixtures = ["test"]

    approved_data = {
        'test1': {'one': [1, 2], 'two': [2, 3]},
        'test2': {'three': [3, 4], 'four': [4, 5]}}

    def setUp(self):
        super(OpenIDRPSummaryTestCase, self).setUp()
        self.account = Account.objects.get_by_email('test@canonical.com')
        self.trust_root = 'http://foo.bar.baz'

    def create_summary(self):
        summary = OpenIDRPSummary.objects.create(
            account=self.account,
            trust_root=self.trust_root, openid_identifier='oid')
        summary.set_approved_data(self.approved_data)
        summary.save()
        return summary

    def test_record_when_readonly(self):
        rm = ReadOnlyManager()
        rm.set_readonly()

        try:
            summary = OpenIDRPSummary.objects.record(self.account,
                                                     self.trust_root)
            self.assertEqual(summary, None)
            self.assertRaises(
                OpenIDRPSummary.DoesNotExist,
                OpenIDRPSummary.objects.get, account=self.account,
                trust_root=self.trust_root, openid_identifier=None)
        finally:
            rm.clear_readonly()

    def test_record_with_existing_and_no_openid_identifier(self):
        summary1 = self.create_summary()
        summary2 = OpenIDRPSummary.objects.record(self.account,
                                                  self.trust_root)
        summary2.set_approved_data(self.approved_data)
        self.assertEqual(summary1.total_logins, 1)
        self.assertEqual(summary2.total_logins, 1)
        self.assertNotEqual(summary1, summary2)

    def test_record_existing_same_oid(self):
        summary1 = self.create_summary()
        summary2 = OpenIDRPSummary.objects.record(
            self.account, self.trust_root, openid_identifier='oid')
        summary2 = OpenIDRPSummary.objects.get(pk=summary2.pk)
        self.assertEqual(summary2.total_logins, 2)
        self.assertEqual(summary1, summary2)

    def test_record_existing_different_oid(self):
        summary1 = self.create_summary()
        summary2 = OpenIDRPSummary.objects.record(
            self.account, self.trust_root, openid_identifier='oid1',
            approved_data=self.approved_data)
        self.assertEqual(summary1.total_logins, 1)
        self.assertEqual(summary2.total_logins, 1)
        self.assertNotEqual(summary1, summary2)

    def test_record_not_existing(self):
        summary1 = OpenIDRPSummary.objects.record(
            self.account, self.trust_root, openid_identifier='oid')
        self.assertEqual(summary1.total_logins, 1)
        summary2 = OpenIDRPSummary.objects.get(
            account=self.account,
            trust_root=self.trust_root, openid_identifier='oid')
        self.assertEqual(summary1, summary2)

    def test_approved_data(self):
        summary = self.create_summary()
        summary.set_approved_data(self.approved_data)
        summary.save()
        summary2 = OpenIDRPSummary.objects.get(
            account=self.account,
            trust_root=self.trust_root, openid_identifier='oid')
        self.assertEqual(summary2.get_approved_data(), self.approved_data)
