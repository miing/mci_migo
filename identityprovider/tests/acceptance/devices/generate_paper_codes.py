# Test google device addition
from sst.actions import *
from u1testutils.sst import config

from identityprovider.tests.acceptance.shared import helpers
from identityprovider.tests.acceptance.shared.devices import (
    click_add_device_button,
    click_add_new_device_link,
    enter_otp,
    store_paper_device,
    update_paper_device,
)

check_flags('paper_device')

config.set_base_url_from_env()

email = helpers.login_or_register_account(device_cleanup=True)

# Go to the authentication devices page
click_link('devices-link')

# Click on "Add a new authentication device" link
click_add_new_device_link()

# Add the paper device
set_radio_value('type_paper')
click_add_device_button()

# Get the first code which we will invalidate
old_code = get_elements_by_css('ol.codelist li')[0].text

# Save the device
store_paper_device('Printable backup codes')

# Generate new codes
click_link(get_element(tag='a', text='Generate new codes'))

# Fetch a new codes
new_code = get_elements_by_css('ol.codelist li')[0].text

# Confirm the new codes
click_button(get_element(tag='button', text='Confirm new codes'))

# Update our stored codes for device removal
update_paper_device('Printable backup codes', counter=1)

# Set "twofactor required" in account preferences
helpers.set_twofactor_to_always_required()
add_cleanup(helpers.set_twofactor_to_required_as_needed)

# Logout and back in again
helpers.logout_and_in()
go_to('/')

# Check the first (invalidated) code fails
enter_otp(old_code)
assert_displayed('id_oath_token')

# Check the new code works
enter_otp(new_code)
assert_url('/')
