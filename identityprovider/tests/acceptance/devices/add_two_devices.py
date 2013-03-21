# Test adding a second device requires 2f authentication
from oath import hotp
from sst.actions import (
    assert_table_has_rows,
    assert_table_row_contains_text,
    assert_url,
    get_element,
    set_radio_value,
    write_textfield,
)
from u1testutils.sst import config

from identityprovider.tests.acceptance.shared import helpers, urls
from identityprovider.tests.acceptance.shared.devices import (
    add_device,
    authenticate,
    click_add_device_button,
    click_add_new_device_link,
    store_device,
)


config.set_base_url_from_env()

helpers.login_or_register_account(device_cleanup=True)

# Add an authentication device
aes_key_1 = add_device('add_two_devices')

# Logout and back in so we are no longer 2f-authenticated
helpers.logout_and_in()

# Click on "Add a new authentication device" link
click_add_new_device_link()

# Authenticate with the first device
authenticate('add_two_devices')

# Choose "Generic HOTP device" and click add device
set_radio_value('type_generic')
click_add_device_button()

# Add a name for the second device
write_textfield(get_element(tag='input', name='name'), 'add_two_devices')

# Enter OTP
aes_key_2 = get_element(name='hex_key').get_attribute('value')
store_device('add_two_devices (1)', aes_key_2)
otp_2 = hotp.hotp(aes_key_2, 0)
write_textfield(get_element(tag='input', name='otp'), otp_2)

# Click "Add device"
click_add_device_button()

# Check we are returned to the devices-list page
assert_url(urls.DEVICES)
# Check our new device is now in the table, with the correct name
assert_table_has_rows('device-list', 2)
# FIXME: remove when sorting is consistent
try:
    assert_table_row_contains_text('device-list', 1,
                                   ['add_two_devices (1)', 'Rename Delete'])
except:
    assert_table_row_contains_text('device-list', 0,
                                   ['add_two_devices (1)', 'Rename Delete'])

# Change the preference to always require 2 factor authentication and save
helpers.set_twofactor_to_always_required()
helpers.logout_and_in()

# login using device 1
authenticate('add_two_devices')
helpers.logout_and_in()

# login using device 2
authenticate('add_two_devices (1)')
