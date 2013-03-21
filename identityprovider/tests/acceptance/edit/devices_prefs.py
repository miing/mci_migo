# Test user two factor preferences
from urllib import quote

from sst.actions import (
    assert_checkbox_value,
    assert_element,
    assert_radio_value,
    assert_url,
    fails,
    get_element,
    go_to,
)
from u1testutils.sst import config

from identityprovider.tests.acceptance.shared.devices import (
    add_device,
    authenticate,
    delete_device,
)

from identityprovider.tests.acceptance.shared import helpers, urls


def get_device_preferences_elements():
    go_to(urls.EDIT)
    always_radio = get_element(tag="input", name="twofactor_required",
                               value="True")
    as_needed_radio = get_element(tag="input", name="twofactor_required",
                                  value="False")
    warn_backup_checkbox = get_element(tag="input",
                                       name="warn_about_backup_device")
    return always_radio, as_needed_radio, warn_backup_checkbox


def assert_device_preferences_not_displayed():
    go_to(urls.EDIT)
    fails(assert_element, tag="input", name="twofactor_required", value="True")
    fails(assert_element, tag="input", name="twofactor_required",
          value="False")
    fails(assert_element, tag="input", name="warn_about_backup_device",
          checked="checked")

config.set_base_url_from_env()

# Create account or login to test account
helpers.login_or_register_account(device_cleanup=True)

# Test preferences form is present but disabled
assert_device_preferences_not_displayed()

# Add an authentication device
add_device('prefs')

# Test preferences form is now visible
elements = get_device_preferences_elements()
always_radio, as_needed_radio, warn_backup_checkbox = elements
# and the default is to not "always" require 2 factor authentication
assert_radio_value(always_radio, False)
assert_radio_value(as_needed_radio, True)
assert_checkbox_value(warn_backup_checkbox, True)

# Logout and back in so we are no longer 2f-authenticated
helpers.logout_and_in()

# Change the preference to always require 2 factor authentication and save
helpers.set_twofactor_to_always_required()
assert_url('/two_factor_auth?next=%s' % quote(urls.EDIT))

# 2 factor login
authenticate()

# Check that "always" is now shown in the user preferences
assert_url(urls.EDIT)

elements = get_device_preferences_elements()
always_radio, as_needed_radio, warn_backup_checkbox = elements
# and the default is to *always* require 2 factor authentication
assert_radio_value(always_radio, True)
assert_radio_value(as_needed_radio, False)
assert_checkbox_value(warn_backup_checkbox, True)

# clean up afterward, delete device
delete_device()

# Check that the 2F is no longer set to 'Always'
#   In response to defect #923808
assert_device_preferences_not_displayed()

# Check that the 2F is no longer required
#   In response to defect #930379
helpers.logout_and_in()
go_to(urls.HOME)
assert_url(urls.HOME)

# Add another device and
go_to(urls.DEVICES)
add_device('another name')

# Change the preference to always require 2 factor authentication and save
helpers.set_twofactor_to_always_required()

# Logging out here tests that the devices clean up function works when
# a test ends up with two-factor required but logged out
helpers.logout_and_in()
