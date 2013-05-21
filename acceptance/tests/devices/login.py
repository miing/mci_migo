# Test logging in with two factor authentication
from sst.actions import (
    assert_displayed,
    assert_text,
    assert_url,
    click_link,
    get_base_url,
    get_element,
    go_to,
)
from u1testutils.sst import config

from acceptance.devices import (
    add_device,
    authenticate,
    enter_otp,
)
from acceptance import helpers


config.set_base_url_from_env()
base_url = get_base_url()

email = helpers.login_or_register_account(device_cleanup=True)

# Go to the authentication devices page
click_link('devices-link')

# Add an authentication device
add_device('login')

# Change the preference to always require 2 factor authentication and save
helpers.set_twofactor_to_always_required()

# Logout and attempt to log back in
helpers.logout_and_in()

#   Should insist on 2F and not give access to '/'
# In response to defect #923814
go_to(base_url)

# Check we are on the 2-factor login page
assert_displayed('id_oath_token')

# Enter an invalid password and submit
enter_otp('foo bar baz')

# Check an error message is shown and we are not logged in
assert_displayed('id_oath_token')
assert_text(get_element(css_class='error'),
            'Please enter a 6-digit or 8-digit one-time password.')

# Enter a valid one time password
authenticate('login')

# Check we are now logged in
assert_url('/')
