# Tests logout button and logout link in login.launchpad.net
from django.conf import settings

from sst.actions import (
    assert_element,
    assert_title,
    click_button,
    click_link,
    get_element_by_css,
    go_to,
    write_textfield,
)
from u1testutils.sst import config

from acceptance import urls

from identityprovider.utils import get_current_brand


# Set to Production, Staging, VPS, Developer etc..
config.set_base_url_from_env()

# login first
go_to(urls.HOME)
write_textfield('id_email', settings.SSO_TEST_ACCOUNT_EMAIL)
write_textfield('id_password', settings.SSO_TEST_ACCOUNT_PASSWORD)
click_button(get_element_by_css('*[data-qa-id="ubuntu_login_button"]'))

# logout by clicking on link
click_link('logout-link')

# no link present in ubuntuone brand
if get_current_brand() != 'ubuntuone':
    assert_element(href="/+login")

# make sure we're logged out
go_to(urls.HOME)
assert_title('Log in')

# login first
write_textfield('id_email', settings.SSO_TEST_ACCOUNT_EMAIL)
write_textfield('id_password', settings.SSO_TEST_ACCOUNT_PASSWORD)
click_button(get_element_by_css('*[data-qa-id="ubuntu_login_button"]'))

# logout by hitting url directly
go_to(urls.LOGOUT)

# no link present in ubuntuone brand
if get_current_brand() != 'ubuntuone':
    assert_element(href="/+login")

# make sure we're logged out
go_to(urls.HOME)
assert_title('Log in')
