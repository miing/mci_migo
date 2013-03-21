# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

import re
import traceback
import socket
import urllib
import urllib2

from django.conf import settings


class CaptchaError(Exception):
    """All instances of CaptchaError have a traceback member."""

    def __init__(self, traceback):
        self.traceback = traceback


class NewCaptchaError(CaptchaError):
    """The dummy member is a blank Captcha response."""

    def __init__(self, traceback, dummy):
        super(NewCaptchaError, self).__init__(traceback)
        self.dummy = dummy


class VerifyCaptchaError(CaptchaError):
    pass


class CaptchaResponse(object):
    """Response returned from _open() in case of error"""

    def __init__(self, code, response, tb=None):
        self.code = code
        self.response = response
        self.traceback = tb
        self.is_error = tb is not None
        self._data = None

    def data(self):
        if self._data:
            return self._data
        if self.response:
            self._data = self.response.read()
            return self._data
        else:
            return None


class Captcha(object):
    """
    Class to capture & abstract interaction with external captcha service.

    Current implementation uses reCaptcha service

    .. note: There's no possibility to actually test verification actually
             returning true, as response, for that you need human interaction.

    Getting new captcha is quite simple:

        >>> captcha = Captcha.new()
        >>> captcha.serialize() #+doctest: ELLIPSIS
        {'captcha_id': ..., 'image_url': ...}

    As is verifying received solution:

        >>> email = 'foo@email.com'
        >>> captcha = Captcha('captcha-id-received-from-client', email)
        >>> captcha.verify("this-is-invalid-solution", ip_addr, email)
        False

    Once verified solution is cached, so calling again to .verify() method is
    very cheap (and returns same result):

        >>> captcha.verify("this-is-invalid-solution", ip_addr, email)
        False

    You can also get original response from reCaptcha:

        >>> print captcha.response.data()
        true
        success

    """

    opener = None

    def __init__(self, captcha_id, image_url=None, response=None):
        assert captcha_id is None or isinstance(captcha_id, basestring)
        assert image_url is None or isinstance(image_url, basestring)
        assert response is None or isinstance(response, CaptchaResponse)
        self.captcha_id = captcha_id
        self.image_url = image_url
        self.response = response

        self._verified = None

        self._setup_opener()

    @classmethod
    def _setup_opener(cls):
        if cls.opener is not None:
            return
        if getattr(settings, 'CAPTCHA_USE_PROXY', False):
            proxy_handler = urllib2.ProxyHandler(settings.CAPTCHA_PROXIES)
            opener = urllib2.build_opener(proxy_handler)
        else:
            opener = urllib2.build_opener()
        cls.opener = opener

    def serialize(self):
        return {
            'captcha_id': self.captcha_id,
            'image_url': self.image_url,
        }

    @classmethod
    def new(cls):
        cls._setup_opener()
        url = (settings.CAPTCHA_API_URL +
               '/challenge?k=%s' % settings.CAPTCHA_PUBLIC_KEY)
        response = cls._open(url)
        if response.is_error:
            raise NewCaptchaError(response.traceback, cls(None, None))

        data = response.data()
        m = re.search(r"challenge\s*:\s*'(.+?)'", data, re.M | re.S)
        if m:
            captcha_id = m.group(1)
            image_url = settings.CAPTCHA_IMAGE_URL_PATTERN % captcha_id
        else:
            captcha_id, image_url = None, None
        return cls(captcha_id, image_url, response)

    @classmethod
    def _open(cls, request):
        default_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(getattr(settings, 'CAPTCHA_TIMEOUT', 10))

        try:
            response = cls.opener.open(request)
        except urllib2.URLError, e:
            # Attribute depends weather we have HTTPError or URLError
            error_code = e.code if hasattr(e, 'code') else e.reason[0]
            if error_code not in (111, 113, 408, 500, 502, 503, 504):
                # 111: Connection refused
                # 113: No route to host
                # 408: Request Timeout
                # 500: Internal Server Error
                # 502: Bad Gateway
                # 503: Service Unavailable
                # 504: Gateway Timeout
                raise
            tb = traceback.format_exc()
            return CaptchaResponse(error_code, None, tb)
        finally:
            socket.setdefaulttimeout(default_timeout)

        return CaptchaResponse(response.code, response, None)

    def verify(self, captcha_solution, remote_ip, email):
        if self._verified is not None:
            return self._verified

        if getattr(settings, 'DISABLE_CAPTCHA_VERIFICATION', False):
            self.response = None
            return True

        if self.check_whitelist(email):
            return True

        if isinstance(captcha_solution, unicode):
            captcha_solution = captcha_solution.encode('utf-8')

        request_data = urllib.urlencode({
            'privatekey': settings.CAPTCHA_PRIVATE_KEY,
            'remoteip': remote_ip,
            'challenge': self.captcha_id,
            'response': captcha_solution,
        })
        request = urllib2.Request(settings.CAPTCHA_VERIFY_URL, request_data)
        self.response = self._open(request)

        if not self.response.is_error:
            response_data = self.response.data()
            self.verified, self.message = response_data.split('\n', 1)
            self._verified = self.verified.lower() == 'true'
        elif self.captcha_id is None:
            self.message = 'no-challenge'
            self._verfied = False
        else:
            self._verified = False
            raise VerifyCaptchaError(self.response.traceback)
        return self._verified

    def check_whitelist(self, email):
        for pattern in settings.EMAIL_WHITELIST_REGEXP_LIST:
            if re.match(pattern, email):
                return True
        return False
