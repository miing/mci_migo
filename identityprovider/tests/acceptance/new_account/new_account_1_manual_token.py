# This test ensures that the token sent via email can be used to verify
# the account.
from sst.actions import (
    assert_text_contains,
    assert_title,
    assert_title_contains,
    click_button,
    get_element,
    go_to,
    write_textfield,
    wait_for,
)
from sst import config as sst_config
from u1testutils import mail
from u1testutils.sst import config
from u1testutils.sst.sso.utils import mail as sso_mail

from identityprovider.tests.acceptance.shared import urls, helpers


config.set_base_url_from_env()

go_to(urls.NEW_ACCOUNT)
assert_title('Create account')

email_address = mail.make_unique_test_email_address()
helpers.fill_registration_form(email_address)

click_button(get_element(name='continue'))

if 'allow_unverified' not in sst_config.flags:
    assert_title_contains('Account creation mail sent')
    assert_text_contains(
        get_element(id='content'),
        r'just emailed .* \(from .*\) to confirm your address\.',
        regex=True)

    vcode = sso_mail.get_verification_code_for_address(email_address)

    write_textfield(get_element(name='confirmation_code'), vcode)
    click_button(get_element(css_class='btn'))

# We know that the confirmation code worked if we are now looking at the
# logged-in details page for the user.
wait_for(assert_title, "My Name's details")
