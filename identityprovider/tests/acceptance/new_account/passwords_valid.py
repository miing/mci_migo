#  password tests: valid passwords
#
# rules:
#   Password must be at least 8 characters long.


from sst.actions import (
    assert_title,
    assert_title_contains,
    click_button,
    get_element,
    go_to,
    wait_for,
)
from sst import config as sst_config
from u1testutils import mail
from u1testutils.sst import config
from u1testutils.sst.sso.utils import mail as sso_mail

from identityprovider.tests.acceptance.shared import urls, helpers


email_address = mail.make_unique_test_email_address()

config.set_base_url_from_env()
go_to(urls.NEW_ACCOUNT)
assert_title('Create account')
helpers.fill_registration_form(email_address, password=password)
click_button(get_element(name='continue'))

if 'allow_unverified' in sst_config.flags:
    wait_for(assert_title, "My Name's details")
else:
    assert_title_contains('Account creation mail sent')
    msg = 'just emailed %s (from noreply@ubuntu.com) to confirm your address.'
    assert (msg % email_address in get_element(id='content').text)

    vcode = sso_mail.get_verification_code_for_address(email_address)
