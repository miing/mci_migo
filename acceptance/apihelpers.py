from sst.actions import assert_equal
from u1testutils import mail

from acceptance import urls
from ssoclient.v2 import V2ApiClient


def get_api_client(default='http://localhost:8000'):
    base_url = urls.get_base_url(default)
    _client = V2ApiClient(base_url + '/api/v2')
    return _client


def register_new_test_account(
        email=None,
        password='Admin007',
        displayname='My Name'):

    if email is None:
        email = mail.make_unique_test_email_address()

    client = get_api_client()
    response = client.register(
        email=email,
        password=password,
        displayname=displayname,
        captcha_id="XYZ",
        captcha_solution="XYZ",
    )
    return response.json(), password


def assert_api_error(body, code):
    assert 'code' in body
    assert 'message' in body
    assert 'extra' in body
    assert_equal(body['code'], code)


def fail(msg):
    raise AssertionError(msg)
