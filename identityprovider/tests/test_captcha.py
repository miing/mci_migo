# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).
from urllib2 import HTTPError, URLError
from django.test import TestCase
from mock import Mock, patch

from identityprovider.models.captcha import Captcha
from identityprovider.tests.utils import patch_settings


class CaptchaTestCase(TestCase):

    def test_opener_is_created_during_init(self):
        Captcha.opener = None

        Captcha('test')

        self.assertTrue(Captcha.opener is not None)

    @patch('urllib.urlencode')
    def test_non_ascii_captach_solution(self, mock_urlencode):
        captcha_solution = u'\xa3'
        encoded_solution = captcha_solution.encode('utf-8')
        mock_urlencode.return_value = 'some text'

        with patch_settings(DISABLE_CAPTCHA_VERIFICATION=False):
            captcha = Captcha(None)
            captcha._open = Mock()
            captcha._open.return_value.is_error = True
            captcha.verify(captcha_solution, 'foobar', '')

        captcha_response = mock_urlencode.call_args[0][0]['response']
        self.assertEqual(captcha_response, encoded_solution)

    def test_opener_is_created_when_proxy_is_required(self):
        Captcha.opener = None

        with patch_settings(CAPTCHA_USE_PROXY=True, CAPTCHA_PROXIES={}):
            Captcha('test')

        self.assertTrue(Captcha.opener is not None)

    def test_open_properly_handles_all_expected_error_codes(self):
        handled_codes = [111, 113, 408, 500, 502, 503, 504]

        def mock_open(request):
            code = handled_codes.pop()
            if code < 200:
                raise URLError([code])
            else:
                raise HTTPError(None, code, None, None, None)
        Captcha._setup_opener()
        Captcha.opener.open = mock_open

        while handled_codes:
            response = Captcha._open(None)
            self.assertTrue(response.is_error)

    def test_verify_is_short_circuited_when_disabled_in_settings(self):
        with patch_settings(DISABLE_CAPTCHA_VERIFICATION=True):
            captcha = Captcha('test')
            verify_result = captcha.verify('solution', '127.0.0.1', '')

        self.assertTrue(verify_result)
        self.assertTrue(captcha.response is None)

    def test_serialize(self):
        captcha = Captcha('id', 'image')

        self.assertEqual(captcha.serialize(),
                         {'captcha_id': 'id', 'image_url': 'image'})
