# Test YubiKey device addition
from oath import hotp
from sst.actions import (
    assert_element,
    assert_table_has_rows,
    assert_table_row_contains_text,
    click_link,
    get_element,
    set_radio_value,
    write_textfield,
)
from u1testutils.sst import config

from identityprovider.tests.acceptance.shared import helpers
from identityprovider.tests.acceptance.shared.devices import (
    click_add_device_button,
    click_add_new_device_link,
    store_device,
)


config.set_base_url_from_env()

email = helpers.login_or_register_account(device_cleanup=True)

# Go to the authentication devices page
click_link('devices-link')

# Click on "Add a new authentication device" link
click_add_new_device_link()

# Choose YubiKey and click add device
set_radio_value('type_yubi')
click_add_device_button()

# Check that the YubiKey warning is showing
warning = ('Warning: The YubiKey is shipped with a credential in the '
           'short-press slot')
assert_element(css_class='warning', text_regex=warning)

# set device name
name = get_element(tag='input', name='name')
write_textfield(name, 'add_device_yubikey')

# Add correctly generated OTP
aes_key = get_element(name='hex_key').get_attribute('value')
valid_otp = hotp.hotp(aes_key, 0)
write_textfield(get_element(tag='input', name='otp'), valid_otp)

# Click "Add device"
click_add_device_button()
store_device('add_device_yubikey', aes_key)

# Check our new device is now in the table, with the correct name
assert_table_has_rows('device-list', 1)
assert_table_row_contains_text('device-list', 0,
                               ['add_device_yubikey', 'Delete'], regex=True)
