import re

from raven.processors import Processor
from raven.utils import varmap


# taken from raven 2.0.6 because we can't upgrade to that client version
# without also upgrading the sentry server due to a change in the
# auth api (signature is required by the server but not sent out anymore
# by the newer client).
class RemovePostDataProcessor(Processor):
    """
    Removes HTTP post data.
    """
    def process(self, data, **kwargs):
        if 'sentry.interfaces.Http' in data:
            data['sentry.interfaces.Http'].pop('data', None)

        return data


class RemoveStackLocalsProcessor(Processor):
    """
    Removes local context variables from stacktraces.
    """
    def process(self, data, **kwargs):
        if 'sentry.interfaces.Stacktrace' in data:
            for frame in data['sentry.interfaces.Stacktrace'].get(
                    'frames', []):
                frame.pop('vars', None)

        return data


class SanitizePasswordsProcessor(Processor):
    """
    Asterisk out passwords from password fields in frames, http,
    and basic extra data.
    """
    MASK = '*' * 8
    FIELDS = frozenset(['password', 'secret', 'passwd'])
    VALUES_RE = re.compile(r'^\d{16}$')

    def sanitize(self, key, value):
        if value is None:
            return

        if isinstance(value, basestring) and self.VALUES_RE.match(value):
            return self.MASK

        if not key:  # key can be a NoneType
            return value

        key = key.lower()
        for field in self.FIELDS:
            if field in key:
                # store mask as a fixed length for security
                return self.MASK
        return value

    def filter_stacktrace(self, data):
        if 'frames' not in data:
            return
        for frame in data['frames']:
            if 'vars' not in frame:
                continue
            frame['vars'] = varmap(self.sanitize, frame['vars'])

    def filter_http(self, data):
        for n in ('data', 'cookies', 'headers', 'env', 'query_string'):
            if n not in data:
                continue

            if isinstance(data[n], basestring) and '=' in data[n]:
                # at this point we've assumed it's a standard HTTP query
                querybits = []
                for bit in data[n].split('&'):
                    chunk = bit.split('=')
                    if len(chunk) == 2:
                        querybits.append((chunk[0], self.sanitize(*chunk)))
                    else:
                        querybits.append(chunk)

                data[n] = '&'.join('='.join(k) for k in querybits)
            else:
                data[n] = varmap(self.sanitize, data[n])

    def process(self, data, **kwargs):
        if 'sentry.interfaces.Stacktrace' in data:
            self.filter_stacktrace(data['sentry.interfaces.Stacktrace'])

        if 'sentry.interfaces.Http' in data:
            self.filter_http(data['sentry.interfaces.Http'])

        return data
# end raven processors


# Data structure overview
# =======================
# sentry.interfaces.Http
#   method (request.method)
#   url (request.build_absolute_uri())
#   query_string (request.META['QUERY_STRING'])
#   data
#     if GET -> None
#     if POST -> (request.raw_post_data or request.POST)
#     else -> '<unavailable>'
#   cookies (request.COOKIES)
#   headers
#     HTTP_XXX_YYY -> Xxx-Yyy
#     CONTENT_TYPE -> Content-Type
#     CONTENT_TYPE_LENGTH -> Content-Type-Length
#   env
#     SERVER_PORT
#     SERVER_NAME
#     SERVER_ADDR
# sentry.interfaces.User
#   is_authenticated
#   id
#   username
#   email
# sentry.interfaces.Stacktrace
#   frames
#     vars
# sentry.interfaces.Message
#   message
#   params
# sentry.interfaces.Query
#   query
#   engine
# sentry.interfaces.Exception
#   value
#   type
#   module
#   frames
# sentry.interfaces.Template
#   filename
#   abs_path
#   pre_context
#   lineno
#   post_context

class SanitizeSecretsProcessor(SanitizePasswordsProcessor):
    """
    Asterisk out sensitive data from frames, http, and basic extra data.
    """
    FIELDS = frozenset(['auth', 'token', 'atrequest', 'request'])
    PATTERNS = [
        r'[A-Za-z0-9]{16}',     # token
        r'token/[A-Za-z0-9]+',  # authtoken
        r'[^/]+@[^/]*',         # email address
    ]

    def sanitize(self, key, value):
        if isinstance(value, basestring):
            for pattern in self.PATTERNS:
                # mask sensitive data
                value = re.sub(pattern, self.MASK, value)
        return super(SanitizeSecretsProcessor, self).sanitize(key, value)

    def filter_http(self, data):
        super(SanitizeSecretsProcessor, self).filter_http(data)
        if 'url' in data:
            data['url'] = self.sanitize('url', data['url'])

    def process(self, data):
        super(SanitizeSecretsProcessor, self).process(data)
        # sanitize anything else left unsanitized
        for key in data:
            if key in ('sentry.interfaces.Stacktrace',
                       'sentry.interfaces.Http',
                       'sentry.interfaces.User',
                       'modules'):
                continue
            data[key] = varmap(self.sanitize, data[key])
        return data


class SanitizeCookiesProcessor(Processor):
    """Asterisk out cookie data in HTTP headers."""
    MASK = u'*' * 8

    def filter_http(self, data):
        # sanitize cookies
        if 'cookies' in data:
            cookies = data['cookies']
            for cookie in cookies:
                cookies[cookie] = self.MASK

        # sanitize cookie header
        if 'Cookie' in data.get('headers', {}):
            data['headers']['Cookie'] = self.MASK

        return data

    def process(self, data, **kwargs):
        if 'sentry.interfaces.Http' in data:
            self.filter_http(data['sentry.interfaces.Http'])

        return data


class RemoveUserDataProcessor(Processor):
    """Removes user data."""

    def process(self, data, **kwargs):
        if 'sentry.interfaces.User' in data:
            user_data = data['sentry.interfaces.User']
            for key in ('id', 'username', 'email'):
                user_data.pop(key, None)

        return data
