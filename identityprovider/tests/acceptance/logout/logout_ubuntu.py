# Tests logout button and logout link in login.launchpad.net

from django.conf import settings
from sst.actions import (
    assert_element,
    assert_title,
    click_button,
    click_link,
    get_element,
    go_to,
    write_textfield,
)
from u1testutils.sst import config

import urls


# Set to Production, Staging, VPS, Developer etc..
config.set_base_url_from_env()

# login first
go_to(urls.HOME)
write_textfield('id_email', settings.QA_ACCOUNT_EMAIL)
write_textfield('id_password', settings.QA_ACCOUNT_PASSWORD)
click_button(get_element(name='continue'))
# logout by clicking on link
click_link('logout-link')
assert_element(href="/+login")
# make sure we're logged out
go_to(urls.HOME)
assert_title('Log in')

# login first
write_textfield('id_email', settings.QA_ACCOUNT_EMAIL)
write_textfield('id_password', settings.QA_ACCOUNT_PASSWORD)
click_button(get_element(name='continue'))
# logout by hitting url directly
go_to(urls.LOGOUT)
assert_element(href="/+login")
# make sure we're logged out
go_to(urls.HOME)
assert_title('Log in')
