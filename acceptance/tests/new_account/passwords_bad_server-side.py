#  password tests: server-side validation
#
# rules:
#   Password must be at least 8 characters long.
from sst.actions import (
    assert_attribute,
    assert_text,
    assert_title,
    assert_url,
    click_button,
    get_element,
    go_to,
)
from u1testutils import mail
from u1testutils.sst import config

from acceptance import helpers, urls

from identityprovider.utils import get_current_brand


EMAIL = mail.make_unique_test_email_address()
NAME = 'Some Name'

config.set_base_url_from_env()
go_to(urls.NEW_ACCOUNT)
assert_title('Create account')
helpers.fill_registration_form(EMAIL, displayname=NAME, password=password)
click_button(get_element(name='continue'))

assert_url(urls.NEW_ACCOUNT)
assert_text('id_displayname', NAME)
assert_text('id_email', EMAIL)

if get_current_brand() == 'ubuntuone':
    msg = 'Password with at least 8 characters'
    assert_attribute('id_password', 'placeholder', msg)
else:
    msg = 'Password must be at least 8 characters long.'
    assert_text(get_element(css_class='formHelp'), msg)
