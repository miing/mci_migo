from sst.actions import (
    assert_title,
    assert_title_contains,
    check_flags,
    click_button,
    get_element,
    go_to,
    wait_for,
)
from u1testutils import mail
from u1testutils.sst import config
from u1testutils.sst.sso.utils import mail as sso_mail

from identityprovider.tests.acceptance.shared import helpers


check_flags('allow_unverified')

config.set_base_url_from_env()

email_address = mail.make_unique_test_email_address()
password = "Admin007"
helpers.register_account(email_address, password=password)

wait_for(assert_title, "My Name's details")

helpers.logout()

link = sso_mail.get_verification_link_for_address(email_address)
go_to(link)
wait_for(assert_title, "Log in")

helpers.login(email_address, password)

go_to(link)
click_button(get_element(name='continue'))
wait_for(assert_title_contains, "My Name")
