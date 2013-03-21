from django.conf import settings
from django.test import TestCase

from identityprovider.processors import (
    RemovePostDataProcessor,
    RemoveStackLocalsProcessor,
    RemoveUserDataProcessor,
    SanitizeCookiesProcessor,
    SanitizePasswordsProcessor,
    SanitizeSecretsProcessor,
)

REQUEST_STRING = """<WSGIRequest:
GET:<QueryDict: {}>
POST:<QueryDict: {
    u'csrfmiddlewaretoken': [u'some-value'],
    u'password': [u'some-value'],
    u'passwordconfirm': u['some-value']}>
COOKIES:{'C': '1', 'othercookie': '2'}>"""


class ProcessorTestCaseMixin(object):
    def get_test_data(self):
        """Returns a tuple (data, expected) to be used by the test."""

    def test_process(self):
        data, expected = self.get_test_data()
        processor = self.PROCESSOR(None)
        sanitized = processor.process(data)
        self.assertEqual(sanitized, expected)


class SanitizeSecretsProcessorTestCase(ProcessorTestCaseMixin, TestCase):
    PROCESSOR = SanitizeSecretsProcessor

    def get_test_data(self):
        data = {
            'sentry.interfaces.Stacktrace': {
                'frames': [
                    {'vars': {
                        'request': REQUEST_STRING,
                        'callback_kwargs': {
                            'authtoken': u'foobar',
                            'email_address': u'mark@example.com'}}},
                    {'vars': {
                        'request': REQUEST_STRING,
                        'kwargs': {
                            'authtoken': u'foobar',
                            'email_address': u'mark@example.com'}}},

                    {'vars': {
                        'authtoken': u'foobar',
                        'account': '<Account: Mark Shuttleworth>',
                        'rpconfig': None,
                        'request': REQUEST_STRING,
                        'token': None,
                        'email_address': u'mark@example.com',
                        'atrequest': '<AuthToken: foobar>'}},
                ]
            },
            'sentry.interfaces.User': {
                'is_authenticated': False
            },
            'sentry.interfaces.Http': {
                'cookies': {
                    '__utmz': 'some-value',
                    'csrftoken': 'some-value',
                    '__utma': 'some-value',
                    '__utmb': 'some-value',
                    '__utmc': 'some-value',
                    settings.SESSION_COOKIE_NAME: 'some-value',
                    'C': '1',
                },
                'url': 'http://localhost:8000/token/foobar/'
                       '+resetpassword/mark@example.com',
                'headers': {
                    'Content-Length': '99',
                    'Accept-Language': 'en-us,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'Host': 'localhost:8000',
                    'Accept': 'text/html,application/xhtml+xml,'
                              'application/xml;q=0.9,*/*;q=0.8',
                    'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; '
                                  'rv:15.0) Gecko/20100101 Firefox/15.0.1',
                    'Connection': 'keep-alive',
                    'Referer': 'http://localhost:8000/token/foobar/'
                               '+resetpassword/mark@example.com',
                    'Cache-Control': 'max-age=0',
                    'Cookie': ('__utma=some-value; __utmz=some-value; '
                               '%s=some-value; csrftoken=some-value; C=1; '
                               '__utmc=some-value; __utmb=some-value') %
                              settings.SESSION_COOKIE_NAME,
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                'env': {
                    'SERVER_PORT': '8000',
                    'SERVER_NAME': 'localhost',
                    'REMOTE_ADDR': '127.0.0.1',
                },
                'query_string': 'param1=value1&sometoken=some-value&'
                                'asecret=some-value',
                'data': 'csrfmiddlewaretoken=some-value&password=some-value&'
                        'passwordconfirm=some-value',
                'method': 'POST',
            }
        }

        mask = self.PROCESSOR.MASK
        expected = data.copy()
        expected['sentry.interfaces.Stacktrace']['frames'][0]['vars']
        st_data = expected['sentry.interfaces.Stacktrace']
        http_data = expected['sentry.interfaces.Http']

        st_data['frames'][0]['vars']['request'] = mask
        st_data['frames'][0]['vars']['callback_kwargs']['authtoken'] = mask
        st_data['frames'][1]['vars']['request'] = mask
        st_data['frames'][1]['vars']['kwargs']['authtoken'] = mask
        st_data['frames'][2]['vars']['authtoken'] = mask
        st_data['frames'][2]['vars']['request'] = mask
        st_data['frames'][2]['vars']['atrequest'] = mask
        masked_url = ('http://localhost:8000/%(mask)s/'
                      '+resetpassword/%(mask)s' % {'mask': mask})
        http_data['cookies']['csrftoken'] = mask
        http_data['url'] = masked_url
        http_data['headers']['Referer'] = masked_url
        http_data['headers']['Cookie'] = mask
        http_data['query_string'] = ('param1=value1&sometoken=%s&'
                                     'asecret=some-value' % mask)
        http_data['data'] = ('csrfmiddlewaretoken=%s&password=some-value&'
                             'passwordconfirm=some-value' % mask)

        return data, expected


class SanitizeCookiesProcessorTestCase(ProcessorTestCaseMixin, TestCase):
    PROCESSOR = SanitizeCookiesProcessor

    def get_test_data(self):
        data = {
            'sentry.interfaces.Http': {
                'cookies': {
                    'foo': 'some-value',
                    'bar': 'other-value',
                },
                'headers': {
                    'Cookie': 'foo=some-value; bzr=other-value',
                    'Content-Length': '99',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept-Language': 'en-us,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'Host': 'localhost:8000',
                    'Connection': 'keep-alive',
                    'Referer': 'http://localhost:8000/token/foobar/'
                               '+resetpassword/mark@example.com',
                    'Cache-Control': 'max-age=0',
                },
            },
        }

        mask = self.PROCESSOR.MASK
        expected = data.copy()
        for cookie in expected['sentry.interfaces.Http']['cookies']:
            expected['sentry.interfaces.Http']['cookies'][cookie] = mask
        expected['sentry.interfaces.Http']['headers']['Cookie'] = mask

        return data, expected


class RemoveUserProcessorTestCase(ProcessorTestCaseMixin, TestCase):
    PROCESSOR = RemoveUserDataProcessor

    def get_test_data(self):
        data = {
            'sentry.interfaces.User': {
                'is_authenticated': True,
                'id': 1,
                'username': 'foo',
                'email': 'mark@example.com',
            },
        }

        expected = {
            'sentry.interfaces.User': {
                'is_authenticated': True,
            },
        }

        return data, expected


class CombinedProcessorsTestCase(TestCase):
    def get_test_data(self):
        data = {
            'sentry.interfaces.Stacktrace': {
                'frames': [
                    {'vars': {
                        'request': REQUEST_STRING,
                        'callback_kwargs': {
                            'authtoken': u'foobar',
                            'email_address': u'mark@example.com'}}},
                    {'vars': {
                        'request': REQUEST_STRING,
                        'kwargs': {
                            'authtoken': u'foobar',
                            'email_address': u'mark@example.com'}}},

                    {'vars': {
                        'authtoken': u'foobar',
                        'account': '<Account: Mark Shuttleworth>',
                        'rpconfig': None,
                        'request': REQUEST_STRING,
                        'token': None,
                        'email_address': u'mark@example.com',
                        'atrequest': '<AuthToken: foobar>'}},
                ]
            },
            'sentry.interfaces.User': {
                'is_authenticated': True,
                'id': 1,
                'username': 'foo',
                'email': 'mark@example.com',
            },
            'sentry.interfaces.Http': {
                'cookies': {
                    '__utmz': 'some-value',
                    'csrftoken': 'some-value',
                    '__utma': 'some-value',
                    '__utmb': 'some-value',
                    '__utmc': 'some-value',
                    settings.SESSION_COOKIE_NAME: 'some-value',
                    'C': '1',
                },
                'url': 'http://localhost:8000/token/foobar/'
                       '+resetpassword/mark@example.com',
                'headers': {
                    'Content-Length': '99',
                    'Accept-Language': 'en-us,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'Host': 'localhost:8000',
                    'Accept': 'text/html,application/xhtml+xml,'
                              'application/xml;q=0.9,*/*;q=0.8',
                    'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; '
                                  'rv:15.0) Gecko/20100101 Firefox/15.0.1',
                    'Connection': 'keep-alive',
                    'Referer': 'http://localhost:8000/token/foobar/'
                               '+resetpassword/mark@example.com',
                    'Cache-Control': 'max-age=0',
                    'Cookie': ('__utma=some-value; __utmz=some-value; '
                               '%s=some-value; csrftoken=some-value; C=1; '
                               '__utmc=some-value; __utmb=some-value') %
                              settings.SESSION_COOKIE_NAME,
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                'env': {
                    'SERVER_PORT': '8000',
                    'SERVER_NAME': 'localhost',
                    'REMOTE_ADDR': '127.0.0.1',
                },
                'query_string': 'param1=value1&sometoken=some-value&'
                                'asecret=some-value',
                'data': 'csrfmiddlewaretoken=some-value&password=some-value&'
                        'passwordconfirm=some-value',
                'method': 'POST',
            }
        }

        # all processors have the same mask, so pick any
        mask = SanitizePasswordsProcessor.MASK
        masked_url = ('http://localhost:8000/%(mask)s/'
                      '+resetpassword/%(mask)s' % {'mask': mask})
        expected = {
            'sentry.interfaces.Stacktrace': {
                'frames': [{}, {}, {}],
            },
            'sentry.interfaces.User': {
                'is_authenticated': True
            },
            'sentry.interfaces.Http': {
                'cookies': {
                    '__utmz': mask,
                    'csrftoken': mask,
                    '__utma': mask,
                    '__utmb': mask,
                    '__utmc': mask,
                    settings.SESSION_COOKIE_NAME: mask,
                    'C': mask,
                },
                'url': masked_url,
                'headers': {
                    'Content-Length': '99',
                    'Accept-Language': 'en-us,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'Host': 'localhost:8000',
                    'Accept': 'text/html,application/xhtml+xml,'
                              'application/xml;q=0.9,*/*;q=0.8',
                    'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; '
                                  'rv:15.0) Gecko/20100101 Firefox/15.0.1',
                    'Connection': 'keep-alive',
                    'Referer': masked_url,
                    'Cache-Control': 'max-age=0',
                    'Cookie': mask,
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                'env': {
                    'SERVER_PORT': '8000',
                    'SERVER_NAME': 'localhost',
                    'REMOTE_ADDR': '127.0.0.1',
                },
                'query_string': 'param1=value1&sometoken=%(mask)s&'
                                'asecret=%(mask)s' % {'mask': mask},
                'method': 'POST',
            }
        }

        return data, expected

    def test_process(self):
        processors = [
            RemovePostDataProcessor(None),
            RemoveStackLocalsProcessor(None),
            SanitizePasswordsProcessor(None),
            RemoveUserDataProcessor(None),
            SanitizeSecretsProcessor(None),
            SanitizeCookiesProcessor(None),
        ]

        data, expected = self.get_test_data()
        for processor in processors:
            data = processor.process(data)
        self.assertEqual(data, expected)
