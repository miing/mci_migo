# Test that after 18 failed attempts at two factor authentication the account
# is logged out and suspended
from sst.actions import (
    assert_displayed,
    assert_element,
    wait_for,
)
from u1testutils.sst import config

from identityprovider.tests.acceptance.shared import helpers
from identityprovider.tests.acceptance.shared.devices import (
    add_device,
    enter_otp,
)


config.set_base_url_from_env()

# Create a new account
# (We're going to lockout this account so always create a new one)
helpers.register_account()

# Add an authentication device
add_device('add_two_devices')

# Change the preference to always require 2 factor authentication and save
helpers.set_twofactor_to_always_required()

# Logout and attempt to log back in
helpers.logout_and_in()

# Enter an incorrect otp 18 times to trigger account suspension
for _ in range(18):
    # Check we are on the 2-factor login page
    wait_for(assert_displayed, 'id_oath_token')

    # Enter an incorrect password and submit
    enter_otp('12345678')

# The account is now suspended
assert_element(tag='h1', text='Account suspended')
