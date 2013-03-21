# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from unittest import TestCase
from identityprovider.signed import dumps, loads, sign, unsign, BadSignature


class SignedTestCase(TestCase):

    def test_dumps_and_loads(self):
        # 'test'*20 is just for better compression ratio
        d = dumps({'test' * 20: 1})
        self.assertEqual(loads(d), {'test' * 20: 1})

    def test_dumps_and_loads_with_secret(self):
        d = dumps('hello', secret='secretkey')
        self.assertEqual(loads(d, secret='secretkey'), 'hello')

    def test_sign_with_no_key(self):
        value = sign('test')
        self.assertTrue('.' in value)

    def test_unsign_with_no_key(self):
        value = sign('test')
        self.assertEqual(unsign(value), 'test')

    def test_unsign_with_bad_signature(self):
        self.assertRaises(BadSignature, unsign, 'test.value')
