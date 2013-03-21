from sst.actions import (
    assert_text,
    assert_url_contains,
    click_link,
    get_element,
    wait_for,
)
from u1testutils.sst import config

from identityprovider.tests.acceptance.shared import helpers
from identityprovider.tests.acceptance.shared.devices import (
    add_device,
    assert_device,
    assert_no_device,
    rename_device,
)

config.set_base_url_from_env()

# happy path

helpers.login_or_register_account(device_cleanup=True)

# add a new device with unicode character and white space
name = 'rename_device'
add_device(name)
# make sure device exists
assert_device(name)
assert_no_device('rename_device_new')
# rename device
rename_device(name, 'rename_device_new')
# confirm device renamed
assert_device('rename_device_new')
assert_no_device(name)

# sad paths

# rename escapes content
name = '<script>alert("rename_device");</script>'
rename_device('rename_device_new', name)
assert_device(name)
assert_no_device('rename_device_new')

# try to rename to empty string
rename_device(name, '')
# rename should have failed
assert_url_contains('/device-rename/\d+', regex=True)
# check error message
assert_text('name-error', 'This field is required.')
# cancel and go back
click_link(get_element(tag='a', text='cancel'))

# spaces get trimmed
rename_device(name, ' ')
# rename should have failed
assert_url_contains('/device-rename/\d+', regex=True)
# check error message
wait_for(assert_text, 'name-error',
         'The name must contain at least one non-whitespace character.')
# cancel and go back
click_link(get_element(tag='a', text='cancel'))
