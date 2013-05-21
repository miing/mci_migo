from sst import actions
from u1testutils.sst import config

from acceptance import apihelpers, helpers


config.set_base_url_from_env()
client = apihelpers.get_api_client()

# Create an account
email_address = helpers.register_account()

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
