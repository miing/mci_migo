# 6) Ensure tokens work from the email, and also clicking the
# link in the email works.
from sst.actions import (
    assert_element,
    assert_title_contains,
    click_button,
    get_element,
    go_to,
    wait_for,
    write_textfield,
)
from u1testutils import mail
from u1testutils.sso import mail as sso_mail
from u1testutils.sst import config

from acceptance import helpers, urls


config.set_base_url_from_env()
NAME = 'Some Name'

# Register the primary account.
primary_email = helpers.register_account(displayname=NAME)

# Register a secondary email, and grab the link from the email sent to
# the secondary address.
secondary_email = mail.make_unique_test_email_address()
go_to(urls.EMAILS)
wait_for(assert_title_contains, "'s email addresses")
write_textfield('id_newemail', secondary_email)
click_button(get_element(name='continue'))
link = sso_mail.get_verification_link_for_address(secondary_email)

# Follow the link from the email to ensure it verifies the secondary
# address.
go_to(link)
click_button(get_element(name='continue'))
wait_for(assert_element, **{'data-qa-id': 'edit_account'})
