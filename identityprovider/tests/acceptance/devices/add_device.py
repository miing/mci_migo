# Test basic device-list page
import sst

from oath import hotp

from sst.actions import (
    assert_element,
    assert_radio_value,
    assert_table_has_rows,
    assert_table_row_contains_text,
    assert_text,
    assert_url,
    click_link,
    fails,
    get_element,
    go_to,
    set_radio_value,
    start,
    stop,
    write_textfield,
)
from u1testutils.sst import config

from identityprovider.tests.acceptance.shared import helpers, urls
from identityprovider.tests.acceptance.shared.devices import (
    click_add_device_button,
    click_add_new_device_link,
    store_device,
)


config.set_base_url_from_env()

helpers.login_or_register_account(device_cleanup=True)

# Go to the authentication devices page
click_link('devices-link')
assert_url(urls.DEVICES)

# Test devices table does not exist
fails(get_element, 'device-list')

# Click on "Add a new authentication device" link
click_add_new_device_link()
# Check url changes correctly
assert_url('/device-addition')

# Click cancel link
click_link(get_element(tag='a', text='cancel'))
# Check we're returned to the devices-list page
assert_url(urls.DEVICES)

# Click on "Add a new authentication device" link
click_add_new_device_link()
assert_element(tag='h1', text_regex='Add a new authentication device')
# Check the correct device options are present
assert_radio_value('type_google', True)
assert_radio_value('type_yubi', False)
assert_radio_value('type_generic', False)

if 'paper_device' in sst.config.flags:
    assert_radio_value('type_paper', False)
else:
    fails(assert_radio_value, 'type_paper', False)

# Choose "Generic HOTP device" and click add device
set_radio_value('type_generic')
click_add_device_button()

# Check page headline changes appropriately
assert_element(tag='h1', text='Add device')

# Check default name
assert_text(get_element(tag="input", type="text", name="name"),
            'Authentication device')
# Check no errors showing
fails(get_element, 'otp-error')
fails(get_element, 'name-error')

# Hit cancel
click_link(get_element(tag='a', text='cancel'))
# Check we are back on the devices list page
assert_url(urls.DEVICES)

# Click on "Add a new authentication device" link
click_add_new_device_link()
# Choose "Generic HOTP device" and click add device
set_radio_value('type_generic')
click_add_device_button()
# Enter a name and meaningless (incorrect) OTP key
write_textfield(get_element(tag='input', name='otp'), 'some invalid key')
# Click "Add device"
click_add_device_button()
# Check error message
assert_text('otp-error',
            'Please enter a 6-digit or 8-digit one-time password.')
fails(get_element, 'name-error')

# Delete name
write_textfield(get_element(tag='input', name='name'), '')
# Click "Add device"
click_add_device_button()
# Check error message
assert_text('name-error', 'This field is required.')
assert_text('otp-error',
            'Please enter a 6-digit or 8-digit one-time password.')

# Add correctly generated OTP
aes_key = get_element(name='hex_key').get_attribute('value')
valid_otp = hotp.hotp(aes_key, 0)
write_textfield(get_element(tag='input', name='otp'), valid_otp)
# Click "Add device"
click_add_device_button()
# Check error message
assert_text('name-error', 'This field is required.')
fails(get_element, 'otp-error')

# Add a name
write_textfield(get_element(tag='input', name='name'), 'add_device')
# Click "Add device"
click_add_device_button()
store_device('add_device', aes_key)

# Check we are returned to the devices-list page
assert_url(urls.DEVICES)

# Stop the browser and restart to ensure 2F Flag is still set
#  Tests defect #930377
stop()
start()
helpers.login()
go_to(urls.DEVICES)

# Check our new device is now in the table, with the correct name
assert_table_has_rows('device-list', 1)
assert_table_row_contains_text('device-list', 0,
                               ['add_device', 'Delete'], regex=True)
