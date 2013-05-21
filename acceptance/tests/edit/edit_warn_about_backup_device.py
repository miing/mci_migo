# Test enabling/disabling the warn_about_backup_device preference

from sst.actions import (
    assert_checkbox_value,
    click_button,
    fails,
    go_to,
    set_checkbox_value,
)
from u1testutils.sst import config

from acceptance.devices import (
    add_device,
    delete_device,
)

from acceptance import helpers, urls


# setup
config.set_base_url_from_env()
helpers.login_or_register_account(device_cleanup=True)

# the test: no warnings if no device
go_to(urls.EDIT)
fails(helpers.get_backup_device_warning_div)
add_device('the single device')

# the test: show warning if missing backup device
helpers.assert_backup_device_warning()

# disable the warn_about_backup_device setting
set_checkbox_value(helpers.get_warn_about_backup_device_checkbox(), False)
click_button(helpers.get_update_preferences_button())
assert_checkbox_value(helpers.get_warn_about_backup_device_checkbox(), False)

# no more warning because user does not want to be warned
fails(helpers.get_backup_device_warning_div)

# re enable the warn_about_backup_device setting
set_checkbox_value(helpers.get_warn_about_backup_device_checkbox(), True)
click_button(helpers.get_update_preferences_button())
assert_checkbox_value(helpers.get_warn_about_backup_device_checkbox(), True)
helpers.assert_backup_device_warning()

# add a second device, ensure that the warning is no longer shown
add_device('the backup device')
fails(helpers.get_backup_device_warning_div)

# delete one device and ensure the warning is back
delete_device()
helpers.assert_backup_device_warning()
