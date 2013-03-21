# Tests logout button and logout link in login.launchpad.net

from django.conf import settings
from sst.actions import (
    assert_element,
    assert_title,
    click_button,
    get_base_url,
    get_element,
    go_to,
    set_base_url,
    write_textfield,
)
from u1testutils.sst import config

from identityprovider.tests.acceptance.shared import helpers, urls


# Set to Production, Staging, VPS, Developer etc..
config.set_base_url_from_env()

helpers.skip_unless_staging_or_production()

# We use the base URL to switch the LP version of SSO here
#   Will work for Staging/Production/VPS etc
base_url = get_base_url()
lp_base_url = base_url.replace('ubuntu.com', 'launchpad.net')
set_base_url(lp_base_url)

# Goes to LP skinned version of SSO to login then,
#   uses the logout button to logout
go_to(urls.HOME)
write_textfield('id_email', settings.QA_ACCOUNT_EMAIL)
write_textfield('id_password', settings.QA_ACCOUNT_PASSWORD)
click_button(get_element(name='continue'))
click_button(get_element(name='logout'))
assert_element(href="/+login")
go_to(urls.HOME)
assert_title('Log in')

# Goes to LP skinned version of SSO to login then,
#   uses the /+logout URL to logout
write_textfield('id_email', settings.QA_ACCOUNT_EMAIL)
write_textfield('id_password', settings.QA_ACCOUNT_PASSWORD)
click_button(get_element(name='continue'))
go_to(urls.LOGOUT)
assert_element(href="/+login")
go_to(urls.HOME)
assert_title('Log in')
