from sst import actions
from ssoclient.v2 import CanNotResetPassword
from u1testutils.sst import config
from u1testutils.sst.sso.utils import mail

from identityprovider.tests.acceptance.shared import apihelpers, helpers


config.set_base_url_from_env()
client = apihelpers.get_api_client()

# Create an account
email_address = helpers.register_account()

# requesting password reset without having the email verified raises error
try:
    response = client.request_password_reset(email_address)
except CanNotResetPassword as error:
    response = error.response
    body = error.body
else:
    helpers.fail("request_password_reset should have thrown "
                 "CanNotResetPassword")

actions.assert_equal(response.status_code, 403)
apihelpers.assert_api_error(body, "CAN_NOT_RESET_PASSWORD")

# verify email address
vlink = mail.get_verification_link_for_address(email_address)
actions.go_to(vlink)
actions.click_button(actions.get_element(name='continue'))

# Request a password reset token
response = client.request_password_reset(email_address)

# Confirm the email address matches
token = response.json()
actions.assert_equal(token['email'], email_address)

# Log out of the web ui
helpers.logout()

# Go to the reset password link
link = helpers.get_password_reset_link(email_address)
actions.go_to(link)

# If the token is valid, then the title of the page will be "Reset password"
actions.assert_title('Reset password')
