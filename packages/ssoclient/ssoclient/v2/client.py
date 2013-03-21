from ssoclient.v2.http import (
    ApiSession,
    api_exception,
)
from ssoclient.v2 import errors

from requests_oauthlib import OAuth1


class V2ApiClient(object):
    """Implements the specific v2 api resources"""

    def __init__(self, endpoint):
        self.session = ApiSession(endpoint)

    def _merge(self, data, extra):
        """Allows data to passed to functions by keyword or dict"""
        if data:
            data.update(extra)
        else:
            data = extra
        return data

    @api_exception(errors.InvalidData)
    @api_exception(errors.CaptchaRequired)
    @api_exception(errors.CaptchaFailure)
    @api_exception(errors.AlreadyRegistered)
    def register(self, data=None, **kwargs):
        return self.session.post('/accounts', data=self._merge(data, kwargs))

    @api_exception(errors.InvalidData)
    @api_exception(errors.AccountSuspended)
    @api_exception(errors.AccountDeactivated)
    @api_exception(errors.InvalidCredentials)
    def login(self, data=None, **kwargs):
        return self.session.post('/tokens/oauth', data=self._merge(data, kwargs))

    @api_exception(errors.InvalidCredentials)
    @api_exception(errors.ResourceNotFound)
    def account_details(self, openid, token=None):
        # if openid and token come directly from a call to client.login
        # then whether they are unicode or byte-strings depends on which
        # json library is in use.
        # oauthlib requires them to be unicode - so we coerce to be sure.
        openid = unicode(openid)
        if token is not None:
            consumer_key = unicode(token['consumer_key'])
            consumer_secret = unicode(token['consumer_secret'])
            token_key = unicode(token['token_key'])
            token_secret = unicode(token['token_secret'])
            oauth = OAuth1(
                consumer_key,
                consumer_secret,
                token_key, token_secret,
            )
        else:
            oauth = None
        return self.session.get('/accounts/%s' % openid, auth=oauth)

    def validate_request(self, data=None, **kwargs):
        return self.session.post('/requests/validate',
                                 data=self._merge(data, kwargs))

    @api_exception(errors.InvalidData)
    @api_exception(errors.AccountSuspended)
    @api_exception(errors.AccountDeactivated)
    @api_exception(errors.ResourceNotFound)
    @api_exception(errors.CanNotResetPassword)
    def request_password_reset(self, email):
        return self.session.post('/tokens/password', data={'email': email})
