# Test google device addition
from sst.actions import (
    assert_element,
    assert_table_has_rows,
    assert_table_row_contains_text,
    assert_url_contains,
    check_flags,
    click_link,
    get_element,
    go_to,
    set_radio_value,
)
from u1testutils.sst import config

from identityprovider.tests.acceptance.shared import helpers
from identityprovider.tests.acceptance.shared.devices import (
    click_add_device_button,
    click_add_new_device_link,
    store_paper_device,
)

check_flags('paper_device')

config.set_base_url_from_env()

email = helpers.login_or_register_account(device_cleanup=True)

# Go to the authentication devices page
click_link('devices-link')

# Click on "Add a new authentication device" link
click_add_new_device_link()

# Choose "paper" device and click add device
set_radio_value('type_paper')
click_add_device_button()

# check the page is correct
assert_url_contains('/device-print/')
assert_element(tag='h1', text='Printable backup codes')

# ol.codelist has list of N codes
assert_element(tag='ol', css_class='codelist')
# make sure print button is visible
assert_element(tag='a', id='printbtn', css_class='btn')

# Go to the device-list page
go_to('/device-list')

# Check our new device is now in the table, with the correct name
assert_table_has_rows('device-list', 1)
texts = ['Printable Backup Codes', 'Rename Delete View Codes']
assert_table_row_contains_text('device-list', 0, texts, regex=True)

# Save the device for cleanup
store_paper_device(name='Printable Backup Codes')

# Go to the print view
click_link(get_element(tag='a', text='View Codes'))
assert_url_contains('/device-print/')

# ol.codelist has list of N codes
assert_element(tag='ol', css_class='codelist')
# make sure print button is visible
assert_element(tag='a', id='printbtn')
