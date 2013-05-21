# Test to make sure nav links to logout still work from deep pages
# (eg: /delete-device/NN)
from sst.actions import (
    assert_element,
    assert_title,
    assert_url_contains,
    click_link,
    go_to,
)
from u1testutils.sst import config

from acceptance import helpers, urls
from acceptance.devices import (
    add_device,
    authenticate,
    click_delete_button,
)

from identityprovider.utils import get_current_brand


config.set_base_url_from_env()

# Create account or login, then add a device
helpers.login_or_register_account(device_cleanup=True)
aes_key = add_device('logout_deep_pages')

# Logout and back in so we are no longer 2f-authenticated
helpers.logout_and_in()

# Create a device to get a deep page and then start to delete it
go_to(urls.DEVICES)
click_delete_button()
authenticate()
assert_url_contains('/device-removal/\d+', regex=True)

# logout by clicking on link
click_link('logout-link')

# no link present in ubuntuone brand
if get_current_brand() != 'ubuntuone':
    assert_element(href="/+login")

# make sure we're logged out
go_to(urls.HOME)
assert_title('Log in')

# login again so that cleanup method can do its work
helpers.logout_and_in()
