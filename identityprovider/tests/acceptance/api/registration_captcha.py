from sst.actions import (
    assert_equal,
    assert_not_equal,
    check_flags,
)
from u1testutils import mail

from ssoclient.v2 import CaptchaRequired

from identityprovider.tests.acceptance.shared import helpers
from identityprovider.tests.acceptance.shared.apihelpers import get_api_client


check_flags('CAPTCHA')
check_flags('ALLOW_UNVERIFIED')

email_address = mail.make_unique_test_email_address()
client = get_api_client()

data = dict(
    email=email_address,
    password='Admin007',
    displayname='My Name',
)

try:
    response = client.register(data)
except CaptchaRequired as error:
    response = error.response
else:
    helpers.fail("register should have thrown CaptchaRequired")

assert_equal(response.status_code, 401)
response_data = response.json()
captcha_id = response_data['extra']['captcha_id']
assert_not_equal(response_data['extra']['image_url'], None)

data['captcha_id'] = captcha_id
data['captcha_solution'] = 'this should be ignored'

response = client.register(data)
assert_equal(response.status_code, 201)
