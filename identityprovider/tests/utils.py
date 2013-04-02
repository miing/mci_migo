# Copyright 2010-2013 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

import sys
import urllib
import urllib2
import urlparse

from cStringIO import StringIO

import gargoyle

from django.conf import settings
from django.contrib.auth.models import AnonymousUser, User
from django.db import DEFAULT_DB_ALIAS, connection
from django.http import HttpRequest
from django.test import TestCase, TransactionTestCase
from django.test.client import RequestFactory
from django.utils import unittest
from django.utils.importlib import import_module
from django.utils.unittest import skipIf
from gargoyle.models import SELECTIVE, Switch
from mock import patch, MagicMock
from oauthlib import oauth1
from openid.message import IDENTIFIER_SELECT
from pyquery import PyQuery

from identityprovider import signed
from identityprovider.models.authtoken import create_token
from identityprovider.tests import DEFAULT_USER_PASSWORD
from identityprovider.tests.factory import SSOObjectFactory
from identityprovider.views import server


# call autodiscover to ensure that the custom condition sets are registered
gargoyle.autodiscover()


MISSING_BACKUP_DEVICE = """
<div class="message warning" id="missing_backup_device">
  <p>
    We strongly recommend having two authentication devices,
    a <strong>primary</strong> device and a <strong>secondary</strong>
    or backup device.
    </br>
    Having two authentication devices means you can continue to access your
    account with your secondary device should your primary device be lost or
    stolen.
    </br>
    </br>
    Click to <a href="{add_device_link}">add a backup device</a>.
  </p>
</div>

"""

EXHAUSTED_WARNING = """Your printed list of backup codes is nearly used up.
  Please print a new list for the following devices."""


def assert_exausted_warning(testcase, devices, response):
    """Helper to assert warning is correctly displayed"""
    dom = PyQuery(response.content)
    warning = dom.find('#exhausted_warning')
    testcase.assertEqual(len(warning), 1)
    elems = warning.find('p')
    testcase.assertEqual(elems[0].text.strip(), EXHAUSTED_WARNING)
    testcase.assertEqual(len(devices), len(elems) - 1)
    for device, elem in zip(devices, elems[1:]):
        testcase.assertIn(device.name, elem.text)
        link = elem.find('a')
        testcase.assertNotEqual(link, None)
        testcase.assertIn("Generate New Codes", link.find('span').text)


def generate_openid_identifier():
    from random import choice
    chars = '34678bcdefhkmnprstwxyzABCDEFGHJKLMNPQRTWXY'
    length = 7

    loop_count = 0
    while loop_count < 20000:
        oid = ''.join(choice(chars) for count in range(length))
        rv = connection.connection.execute(
            ("SELECT COUNT(*) AS num "
             "FROM Account WHERE openid_identifier = ?"), [oid])
        if rv.fetchone()[0] == 0:
            return oid
        loop_count += 1


def create_generate_openid_identifier_function():
    connection.connection.create_function(
        'generate_openid_identifier', 0, generate_openid_identifier)


def authorization_header_from_token(
        url, token, http_method='GET', parameters=None,
        realm='Some client', plaintext=False, base_url='http://testserver'):

    if not isinstance(token, dict):
        token = {
            'token_key': token.token,
            'token_secret': token.token_secret,
            'consumer_key': token.consumer.key,
            'consumer_secret': token.consumer.secret,
        }

    if not url.startswith('http'):
        url = urlparse.urljoin(base_url, url)

    if parameters is not None:
        url += '?' + urllib.urlencode(parameters)

    parts = urlparse.urlparse(url)
    escaped_query = urllib.urlencode(urlparse.parse_qsl(parts.query))
    url = urlparse.urlunparse((
        parts.scheme, parts.netloc, parts.path, parts.params, escaped_query,
        parts.fragment))

    if plaintext:
        signature_method = oauth1.SIGNATURE_PLAINTEXT
    else:
        signature_method = oauth1.SIGNATURE_HMAC

    client = oauth1.Client(
        client_key=token['consumer_key'],
        client_secret=token['consumer_secret'],
        resource_owner_key=token['token_key'],
        resource_owner_secret=token['token_secret'],
        signature_method=signature_method,
        realm=realm,
    )
    uri, header, body = client.sign(url, http_method)
    return {'HTTP_AUTHORIZATION': header['Authorization']}


class patch_settings(object):

    def __init__(self, **kwargs):
        super(patch_settings, self).__init__()
        self.marker = object()
        self.old_settings = {}
        self.kwargs = kwargs

    def start(self):
        for setting, new_value in self.kwargs.items():
            old_value = getattr(settings, setting, self.marker)
            self.old_settings[setting] = old_value
            setattr(settings, setting, new_value)

        self._reload_urls()

    def stop(self):
        for setting, old_value in self.old_settings.items():
            if old_value is self.marker:
                delattr(settings, setting)
            else:
                setattr(settings, setting, old_value)

        self._reload_urls()

    def __enter__(self):
        self.start()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

    def _reload_urls(self, urlconf=None):
        if urlconf is None:
            urlconf = settings.ROOT_URLCONF
        if urlconf in sys.modules:
            reload(sys.modules[urlconf])


class SSOBaseTestCaseMixin(object):
    factory = SSOObjectFactory()

    def _apply_patch(self, *names):
        """Enables a mock.patch, automatically adding it to cleanup"""
        p = patch(".".join(names))
        mock = p.start()
        self.addCleanup(p.stop)
        return mock


class SSOBaseUnittestTestCase(SSOBaseTestCaseMixin, unittest.TestCase):
    pass


class SSOBaseTestCase(SSOBaseTestCaseMixin, TestCase):

    def _pre_setup(self):
        super(SSOBaseTestCase, self)._pre_setup()
        if connection.vendor == 'sqlite':
            create_generate_openid_identifier_function()

    def setUp(self):
        super(SSOBaseTestCase, self).setUp()
        # update db_connections with test database settings
        for conn in settings.DB_CONNECTIONS:
            conn['NAME'] = settings.DATABASES[DEFAULT_DB_ALIAS]['NAME']

    def get_query(self, response):
        query_start = response['Location'].find('?')
        query_str = response['Location'][query_start + 1:]
        query_items = [tuple(item.split('=')) for item in query_str.split('&')]
        query = dict(query_items)
        return query

    def _assign_token_to_rpconfig(self, rpconfig, token=None):
        if token is None:
            token = create_token(16)
        request = {'openid.mode': 'checkid_setup',
                   'openid.trust_root': rpconfig.trust_root,
                   'openid.return_to': rpconfig.trust_root,
                   'openid.identity': IDENTIFIER_SELECT}
        openid_server = server._get_openid_server()
        orequest = openid_server.decodeRequest(request)
        session = self.client.session
        if isinstance(session, dict):
            # Workaround for https://code.djangoproject.com/ticket/11475
            engine = import_module(settings.SESSION_ENGINE)
            session = engine.SessionStore()
            session.save()
            session_cookie = settings.SESSION_COOKIE_NAME
            self.client.cookies[session_cookie] = session.session_key
            cookie_data = {
                'max-age': None,
                'path': '/',
                'domain': settings.SESSION_COOKIE_DOMAIN,
                'secure': settings.SESSION_COOKIE_SECURE or None,
                'expires': None,
            }
            self.client.cookies[session_cookie].update(cookie_data)
        session[token] = signed.dumps(orequest, settings.SECRET_KEY)
        session.save()
        return token

    def conditionally_enable_flag(self, key, field_name, value, condition_set):
        """Setup a gargoyle flag for 'key' in SELECTIVE status."""
        Switch.objects.create(key=key, status=SELECTIVE)
        switch = gargoyle.gargoyle[key]
        switch.add_condition(
            condition_set=condition_set,
            field_name=field_name,
            condition=value,
        )
        self.addCleanup(
            switch.remove_condition,
            condition_set=condition_set,
            field_name=field_name,
            condition=value,
        )


class SSOBaseTransactionTestCase(SSOBaseTestCaseMixin, TransactionTestCase):
    def setUp(self):
        super(SSOBaseTransactionTestCase, self).setUp()
        # update db_connections with test database settings
        for conn in settings.DB_CONNECTIONS:
            conn['NAME'] = settings.DATABASES[DEFAULT_DB_ALIAS]['NAME']


class AuthenticatedTestCase(SSOBaseTestCase):

    login_email = "test@canonical.com"
    login_password = DEFAULT_USER_PASSWORD

    def setUp(self):
        super(AuthenticatedTestCase, self).setUp()
        self.account = self.factory.make_account(email=self.login_email,
                                                 password=self.login_password)
        self.client.login(username=self.login_email,
                          password=self.login_password)


class MockRequest(HttpRequest):

    def __init__(self, path):
        super(HttpRequest, self).__init__()
        self.path = path

        class MockSession(dict):
            def flush(self):
                pass

        self.session = MockSession()

    def get_full_path(self):
        return self.path


class MockHandler(urllib2.HTTPHandler):

    def set_next_response(self, msg):
        self.next_response = msg

    def http_open(self, req):
        response = StringIO(self.next_response)
        resp = urllib.addinfourl(response, {}, req.get_full_url())
        resp.code = 200
        resp.msg = 'OK'
        return resp


skipOnSqlite = skipIf(connection.vendor == 'sqlite', "Skipping on SQLite")


def test_concurrently(times):
    """
    Add this decorator to small pieces of code that you want to test
    concurrently to make sure they don't raise exceptions when run at the
    same time.  E.g., some Django views that do a SELECT and then a subsequent
    INSERT might fail when the INSERT assumes that the data has not changed
    since the SELECT.
    """

    def test_concurrently_decorator(test_func):

        def wrapper(*args, **kwargs):
            exceptions = []
            import threading

            def call_test_func():
                try:
                    test_func(*args, **kwargs)
                except Exception, e:
                    exceptions.append(e)
                    raise

            threads = []
            for i in range(times):
                threads.append(threading.Thread(target=call_test_func))
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            if exceptions:
                raise Exception('test_concurrently intercepted %s exceptions: '
                                '%s' % (len(exceptions), exceptions))
        return wrapper

    return test_concurrently_decorator


class SSORequestFactory(object):
    factory = RequestFactory()

    class FakeSession(dict):
        def cycle_key(self):
            pass

    @staticmethod
    def create_mock_user(**kwargs):
        user = MagicMock(spec=User)
        # id and backend are enough to login
        user.id = 1
        user.backend = 'mock'
        for k, v in kwargs.items():
            setattr(user, k, v)
        return user

    def get(self, url, user=None, session=None, **kwargs):
        request = self.factory.get(url, data=kwargs)
        self._setup(request, user, session)
        return request

    def post(self, url, user=None, session=None, **kwargs):
        request = self.factory.post(url, data=kwargs)
        self._setup(request, user, session)
        return request

    def _setup(self, request, user, session):
        if user is None:
            user = AnonymousUser()
        if session is None:
            session = self.FakeSession()
        request.user = user
        request.session = session


class TeamConditionSelectiveMixin(object):

    team = 'awesomener'
    key = ''

    def enable_flag(self):
        field_name = 'team'
        value = self.team
        condition_set = ('identityprovider.gargoyle.LPTeamConditionSet('
                         'lp_team)')
        self.conditionally_enable_flag(self.key, field_name, value,
                                       condition_set)

    def make_account(self):
        account = self.factory.make_account(email=self.email,
                                            password=self.password)
        # bind account with the team
        team = self.factory.make_team(name=self.team)
        self.factory.add_account_to_team(account, team)
        return account
