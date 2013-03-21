# Test removing a device
from sst.actions import (
    assert_element,
    assert_table_has_rows,
    assert_url,
    assert_url_contains,
    click_button,
    click_link,
    fails,
    get_element,
)
from u1testutils.sst import config

from identityprovider.tests.acceptance.shared import helpers, urls
from identityprovider.tests.acceptance.shared.devices import (
    add_device,
    authenticate,
    click_delete_button,
    remove_device,
)


config.set_base_url_from_env()

helpers.login_or_register_account(device_cleanup=True)

# Add an authentication device
add_device('delete_device')

# Logout and back in so we are no longer 2f-authenticated
helpers.logout_and_in()

# Click on the delete button
click_delete_button()

# Authenticate with the first device
authenticate('delete_device')

# Check the url has changed appropriately
assert_url_contains('/device-removal/\d+', regex=True)
# and the correct device headline is shown
assert_element(tag='h2', text='delete_device')

# Click on cancel
click_link(get_element(tag='a', text='cancel'))

# Check the device is still in the devices table
assert_table_has_rows('device-list', 1)

# Click on the delete button
click_delete_button()

# Click on ok
click_button(get_element(tag='button', text='Delete this device'))
remove_device('delete_device')
# Check we are back on the device-list page
assert_url(urls.DEVICES)

# Check that our device has been deleted
fails(get_element, 'device-list')
