# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from base64 import b16encode
from oath.hotp import hotp
from django.conf import settings

from identityprovider.models import AuthenticationDevice
from identityprovider.tests.utils import SSOBaseTestCase


class DeviceTestCase(SSOBaseTestCase):

    def setUp(self):
        super(DeviceTestCase, self).setUp()
        self.account = self.factory.make_account()
        self.key = b16encode('A' * 20)
        self.device = self.factory.make_device(account=self.account,
                                               key=self.key)

    def test_authenticate_valid_dec6(self):
        otp = hotp(self.key, 0, 'dec6')
        self.assertTrue(self.device.authenticate(otp))
        self.assertEqual(self.device.counter, 1)

    def test_authenticate_valid_dec8(self):
        otp = hotp(self.key, 0, 'dec8')
        self.assertTrue(self.device.authenticate(otp))
        self.assertEqual(self.device.counter, 1)

    def test_authenticate_valid_with_max_drift(self):
        otp = hotp(self.key, settings.HOTP_DRIFT)
        self.assertTrue(self.device.authenticate(otp))
        self.assertEqual(self.device.counter, settings.HOTP_DRIFT + 1)

    def test_authenticate_fails_with_max_plus_1_drift(self):
        otp = hotp(self.key, settings.HOTP_DRIFT + 1)
        self.assertFalse(self.device.authenticate(otp))
        self.assertEqual(self.device.counter, 0)

    def test_ordering(self):
        d1 = self.factory.make_device(self.account, name='foo')
        d2 = self.factory.make_device(self.account, name='bar')
        self.assertEqual(
            [x.id for x in AuthenticationDevice.objects.all().order_by('-id')],
            [x.id for x in d2, d1, self.device])
        self.assertEqual(
            [x.id for x in AuthenticationDevice.objects.all()],
            [x.id for x in self.device, d1, d2])
