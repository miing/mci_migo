# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

import unittest
import urllib2

from mock import (
    Mock,
    patch,
)

from cStringIO import StringIO

from identityprovider.models.captcha import (
    Captcha,
    CaptchaResponse,
    NewCaptchaError,
    VerifyCaptchaError,
)

from identityprovider.tests.utils import patch_settings


class CaptchaResponseTestCase(unittest.TestCase):

    def test_no_data(self):
        r = CaptchaResponse(200, None)
        self.assertEqual(r.data(), None)

    def test_data_from_response(self):
        resp = StringIO('this is the response')
        r = CaptchaResponse(200, resp)
        self.assertEqual(r._data, None)
        self.assertEqual(r.data(), 'this is the response')

    def test_data_exists(self):
        r = CaptchaResponse(200, None)
        r._data = 'this is the data'
        self.assertEqual(r.data(), 'this is the data')


class CaptchaTestCase(unittest.TestCase):

    @patch.object(Captcha, '_open')
    def test_new_captcha_error(self, mock_open):
        self.assertRaises(NewCaptchaError, Captcha.new)

    @patch.object(Captcha, '_open')
    def test_new_captcha_no_challenge(self, mock_open):
        try:
            Captcha.new()
        except NewCaptchaError, e:
            self.assertEqual(e.dummy.captcha_id, None)
            self.assertEqual(e.dummy.image_url, None)

    def test_captcha_open(self):

        class MockOpener(object):

            def open(self, request):
                raise urllib2.URLError((-1, 'error'))

        old_opener = Captcha.opener
        Captcha.opener = MockOpener()
        self.addCleanup(setattr, Captcha, 'opener', old_opener)

        self.assertRaises(urllib2.URLError, Captcha.new)


class CaptchaVerifyTestCase(unittest.TestCase):

    def setUp(self):
        super(CaptchaVerifyTestCase, self).setUp()
        p = patch_settings(DISABLE_CAPTCHA_VERIFICATION=False)
        p.start()
        self.addCleanup(p.stop)

    @patch.object(Captcha, '_open')
    def test_verify_calls_check_whitelist(self, mock_open):
        captcha = Captcha(None)
        captcha.check_whitelist = Mock(return_value=False)

        result = captcha.verify(None, 'localhost', 'foo')
        self.assertFalse(result)
        self.assertTrue(mock_open.called)

        captcha.check_whitelist.assert_called_with('foo')

    @patch.object(Captcha, '_open')
    def test_check_whitelist_match(self, mock_open):
        captcha = Captcha(None)

        regexps = ['not a match', '^foo$']
        with patch_settings(
                EMAIL_WHITELIST_REGEXP_LIST=regexps
        ):
            result = captcha.verify(None, 'localhost', 'foo')
            self.assertTrue(result)
            self.assertFalse(mock_open.called)

    @patch.object(Captcha, '_open')
    def test_check_whitelist_no_match(self, mock_open):
        captcha = Captcha(None)

        regexps = ['not a match', '^bar$']
        with patch_settings(
                EMAIL_WHITELIST_REGEXP_LIST=regexps
        ):
            result = captcha.verify(None, 'localhost', 'foo')
            self.assertFalse(result)
            self.assertTrue(mock_open.called)

    @patch.object(Captcha, '_open')
    def test_verify_already_verified(self, mock_open):
        c = Captcha(None)
        c._verified = True
        r = c.verify(None, None, '')
        self.assertTrue(r)

    @patch.object(Captcha, '_open')
    def test_verify_no_verification(self, mock_open):
        with patch_settings(DISABLE_CAPTCHA_VERIFICATION=True):
            c = Captcha(None)
            r = c.verify(None, None, '')
            self.assertTrue(r)

    def test_verify_response_ok(self):
        @classmethod
        def mock_open(cls, request):
            r = CaptchaResponse(200, StringIO('true\nok'))
            return r
        old_open = Captcha._open
        Captcha._open = mock_open

        try:
            c = Captcha.new()
            r = c.verify(None, "localhost", '')

            self.assertTrue(r)
            self.assertEqual(c.message, 'ok')
        finally:
            Captcha._open = old_open

    @patch.object(Captcha, '_open')
    def test_verify_no_captcha_id(self, mock_open):
        c = Captcha(None)
        r = c.verify(None, 'localhost', '')

        self.assertFalse(r)
        self.assertEqual(c.message, 'no-challenge')

    @patch.object(Captcha, '_open')
    def test_verify_error(self, mock_open):
        c = Captcha(None)
        c.captcha_id = 'challenge-id'

        self.assertRaises(
            VerifyCaptchaError, c.verify, None, 'localhost', ''
        )
