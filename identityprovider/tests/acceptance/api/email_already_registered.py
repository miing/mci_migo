from sst.actions import (
    assert_equal,
)

from ssoclient.v2 import AlreadyRegistered

from identityprovider.tests.acceptance.shared import helpers
from identityprovider.tests.acceptance.shared.apihelpers import (
    assert_api_error,
    get_api_client,
    register_new_test_account,
)


account, password = register_new_test_account()

data = dict(
    email=account['email'],
    password='whatever',
    displayname='something',
    captcha_id='XYZ',
    captcha_solution='XYZ',
)

client = get_api_client()

body = None
try:
    response = client.register(data)
except AlreadyRegistered as error:
    response = error.response
    body = error.body
else:
    helpers.fail("register should have thrown AlreadyRegistered")

assert_equal(response.status_code, 409)
assert_api_error(body, "ALREADY_REGISTERED")
assert 'email' in body['extra']
assert_equal(body['extra']['email'], account['email'])
