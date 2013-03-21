import functools
import json

import requests

JSON = 'application/json'


class ServerError(Exception):
    """An unexpected (5xx) response"""
    def __init__(self, response):
        self.response = response
        super(ServerError, self).__init__(
            "%s : %s" % (response.status_code, response.text)
        )


class ApiException(Exception):
    """An expected error returned by the api (a 4XX)

    Parse the standard error reponse format.
    """
    def __init__(self, response, body=None, msg=None):
        body = body or {}
        self.response = response
        self.body = body
        self.error_message = body.get('message')
        self.extra = body.get('extra', {})
        if msg is None:
            # code *should* be the same as the error_code attribute
            # but won't be for raising an ApiException directly instead
            # of from a subclass - so still fetch it from the payload body
            code = body.get('code')
            msg = "%s: %s" % (response.status_code, code)
        super(ApiException, self).__init__(msg)


def api_exception(exception_class):
    """Register an exception to be raised

    Parse the response from the decorated function, and if it's 400,
    look for the registered ApiException subclass to raise, else raise
    a generic ApiException.
    """

    assert issubclass(exception_class, ApiException)
    code = exception_class.error_code
    assert code, "ApiException subclass requires a valid error_code attribute"

    def decorator(func):
        if hasattr(func, '_api_exceptions'):
            func._api_exceptions[code] = exception_class
            return func

        api_exceptions = {code: exception_class}

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            response = func(*args, **kwargs)
            code = body = None
            try:
                body = response.json()
            except ValueError:
                # simplejson raises JSONDecodeError for invalid json
                # json raises ValueError. JSONDecodeError is a subclass
                # of ValueError - so this catches either.
                pass
            else:
                code = body.get('code')

            if 400 <= response.status_code < 500:
                if code:
                    if code in api_exceptions:
                        exception_class = api_exceptions[code]
                        raise exception_class(response, body)
                    raise ApiException(response, body)
                msg = "Invalid 4XX response"
                raise ApiException(response, body, msg=msg)

            return response

        wrapper._api_exceptions = api_exceptions
        return wrapper
    return decorator


class ApiSession(requests.Session):
    """An SSO api specfic Session

    Adds support for a url endpoint, 500 exceptions, and JSON request body
    handling.
    """

    def __init__(self, endpoint):
        super(ApiSession, self).__init__()
        self.endpoint = endpoint.rstrip('/') + '/'
        # sent with every request
        self.headers['Accept'] = JSON

    def request(self, method, url, **kwargs):
        if 'headers' not in kwargs:
            kwargs['headers'] = {}
        if 'data' in kwargs:
            kwargs['data'] = json.dumps(kwargs['data'])
            kwargs['headers']['Content-Type'] = JSON
        url = self.endpoint + url.lstrip('/')
        response = super(ApiSession, self).request(method, url, **kwargs)
        if response.status_code >= 500:
            raise ServerError(response)
        return response
