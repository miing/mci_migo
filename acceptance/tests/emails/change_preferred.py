from sst.actions import (
    click_button,
    get_element,
    go_to,
    set_dropdown_value,
)
from u1testutils import mail
from u1testutils.sst import config

from acceptance import helpers, urls


config.set_base_url_from_env()

# Register the primary account.
primary_email_id = mail.make_unique_test_email_address()
helpers.register_account(primary_email_id, verify=True)

# Register a secondary email.
secondary_email_id = mail.make_unique_test_email_address()
vcode = helpers.add_email(secondary_email_id)
helpers.try_to_validate_email(secondary_email_id, vcode)

# Change the preferred email.
go_to(urls.HOME)
select = get_element(tag='select', id='id_preferred_email')
set_dropdown_value(select, secondary_email_id)
click_button(get_element(name='update'))

# Check that we got a notification e-mail to the *original* preferred
# address, and mentioning the *new* preferred address.
email_msg = mail.get_latest_email_sent_to(primary_email_id)
mail.email_subject_includes(email_msg, 'E-mail change notification')
mail.email_body_includes(email_msg, secondary_email_id)
