# Test enabling/disabling the warn_about_backup_device preference

from sst.actions import (
    fails,
    go_to,
)
from u1testutils.sst import config

from identityprovider.tests.acceptance.shared.devices import (
    add_device,
    delete_device,
)
from identityprovider.tests.acceptance.shared import helpers, urls


# setup
config.set_base_url_from_env()
helpers.login_or_register_account(device_cleanup=True)

# the test: no warnings if no device
go_to(urls.DEVICES)
fails(helpers.get_backup_device_warning_div)
add_device('the single device')

# the test: show warning if missing backup device
helpers.assert_backup_device_warning()

# add a second device, ensure that the warning is no longer shown
add_device('the backup device')
fails(helpers.get_backup_device_warning_div)

# delete one device and ensure the warning is back
delete_device()
helpers.assert_backup_device_warning()
