from __future__ import absolute_import

import re
import string
import time
from contextlib import contextmanager

from django.conf import settings
from django.test import TestCase
from django.utils.http import http_date


# Original snippet from http://djangosnippets.org/snippets/2156/
class SettingDoesNotExist:
    pass


def switch_settings(**kwargs):
    """Helper method that updates settings and returns old settings."""
    old_settings = {}
    for key, new_value in kwargs.items():
        old_value = getattr(settings, key, SettingDoesNotExist)
        old_settings[key] = old_value

        if new_value is SettingDoesNotExist:
            delattr(settings, key)
        else:
            setattr(settings, key, new_value)

    return old_settings


@contextmanager
def patch_settings(**kwargs):
    old_settings = switch_settings(**kwargs)
    try:
        yield
    finally:
        switch_settings(**old_settings)
# end snippet


class CsrfMiddlewareEnabledTestCase(TestCase):
    def setUp(self):
        # make sure csrf middleware is enabled
        self.old_MIDDLEWARE_CLASSES = settings.MIDDLEWARE_CLASSES
        settings.MIDDLEWARE_CLASSES = [
            'django.middleware.common.CommonMiddleware',
            'django.contrib.csrf.middleware.CsrfMiddleware',
            'django.contrib.sessions.middleware.SessionMiddleware',
            'django.contrib.auth.middleware.AuthenticationMiddleware',
        ]

    def tearDown(self):
        settings.MIDDLEWARE_CLASSES = self.old_MIDDLEWARE_CLASSES

    def get_csrf_token(self, response):
        # get csrf token
        csrf_token_re = re.compile(r"name='csrfmiddlewaretoken' value='(.*)'")
        match = re.search(csrf_token_re, response.content)
        token = match.group(1)
        return token


class NeverCacheTestCase(TestCase):
    def is_cacheable(self, response):
        result = True
        if 'Expires'in response:
            expires = response['Expires']
            now = http_date(time.time())
            result &= expires > now
        if 'Cache-Control' in response:
            cache_control = response['Cache-Control']
            values = map(string.strip, cache_control.split(','))
            for value in values:
                if '=' in value:
                    k, v = value.split('=')
                    if k == 'max-age':
                        result &= int(v) > 0
                        break
        return result
