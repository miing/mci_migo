# Tests logout button on launchpad.net

from sst.actions import (
    assert_element,
    click_button,
    click_link,
    get_base_url,
    get_element,
    go_to,
    set_base_url,
)
from u1testutils.sst import config

from identityprovider.tests.acceptance.shared import helpers, urls


# Set to Production, Staging, VPS, Developer etc..
config.set_base_url_from_env()

#   This test cannot run on VPS/Developer instances since it
#   requires the full Launchpad.
helpers.skip_unless_staging_or_production()

# Getting rid of the 'login' portion of the URL and set LP URL
base_url = get_base_url()
lp_base_url = base_url.replace('ubuntu.com', 'launchpad.net')
lp_base_url = lp_base_url.replace('login.', '')
set_base_url(lp_base_url)

# go to launchpad
go_to(urls.HOME)
# and log in from there
click_link(get_element(text='Log in / Register'))
helpers.login_from_redirect()
# go to launchpad
go_to(urls.HOME)
# and log out from there
click_button(get_element(name='logout'))
# go to launchpad
go_to(urls.HOME)
assert_element(text='Log in / Register')
