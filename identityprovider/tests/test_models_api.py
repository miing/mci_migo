# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from identityprovider.models.api import APIUser
from identityprovider.utils import encrypt_launchpad_password, generate_salt
from identityprovider.tests.utils import SSOBaseTestCase


class APIUserTestCase(SSOBaseTestCase):

    def setUp(self):
        super(APIUserTestCase, self).setUp()

        self.salt = generate_salt()
        self.user = APIUser(username='username')
        self.user.set_password('password', salt=self.salt)
        self.user.save()

    def test_set_password(self):
        self.user.set_password('otherpassword', salt=self.salt)
        expected = encrypt_launchpad_password('otherpassword', salt=self.salt)
        self.assertEqual(self.user.password, expected)

    def test_verify_password(self):
        self.user.set_password('password', salt=self.salt)
        self.assertFalse(self.user.verify_password('otherpassword'))
        self.assertTrue(self.user.verify_password('password'))

    def test_authenticate_user_exists(self):
        user = APIUser.authenticate('username', 'password')
        self.assertEqual(user, self.user)

    def test_authenticate_wrong_password(self):
        user = APIUser.authenticate('username', 'otherpassword')
        self.assertEqual(user, None)

    def test_authenticate_user_does_not_exist(self):
        user = APIUser.authenticate('bad_user', 'password')
        self.assertEqual(user, None)

    def test_unicode(self):
        self.assertEqual(unicode(self.user), u'username')
