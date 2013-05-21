from sst.actions import (
    assert_element,
    click_button,
    get_element,
    go_to,
)
from sst import config as sst_config
from u1testutils import mail
from u1testutils.sst import config

from acceptance import helpers, urls


config.set_base_url_from_env()
email_address = helpers.register_account()

# We logout now and verify that we can't create a second email account
# with the same email address.
go_to(urls.LOGOUT)
go_to(urls.NEW_ACCOUNT)
helpers.fill_registration_form(email_address)
click_button(get_element(name='continue'))

if 'allow_unverified' in sst_config.flags:
    assert_element(text='Invalid Email')
else:
    # In this case, the email sent should be a warning with a link to the
    # forgot password page.
    email = mail.get_latest_email_sent_to(email_address)
    mail.email_subject_includes(email, "Warning")
    mail.email_body_includes(email, "/+forgot_password")
