from sst.actions import (
    assert_text_contains,
    assert_title_contains,
    check_flags,
    click_button,
    get_element,
    get_element_by_css,
    go_to,
    wait_for,
    write_textfield,
)
from u1testutils import mail
from u1testutils.sst import config
from u1testutils.sst.sso.utils import mail as sso_mail

from identityprovider.tests import DEFAULT_USER_PASSWORD
from identityprovider.tests.acceptance.shared import helpers, urls


check_flags('allow_unverified')

config.set_base_url_from_env()

# Register a new account
helpers.register_account(password=DEFAULT_USER_PASSWORD)

# Add a new email, but do not validate it
go_to(urls.EMAILS)
wait_for(assert_title_contains, "email addresses")
new_email = mail.make_unique_test_email_address()
write_textfield('id_newemail', new_email)
click_button(get_element(name='continue'))

link = sso_mail.get_invalidation_link_for_address(new_email)
assert link is not None, 'Invalidation link should not be None.'

go_to(link)
wait_for(assert_title_contains, 'Email invalidation')

msg = 'Are you sure you want to invalidate the email address %s?' % new_email
assert_text_contains(get_element_by_css('div.info'), msg)

click_button(get_element(name='invalidate'))
wait_for(assert_title_contains, 'Email invalidated')
msg = 'The email %s was successfully invalidated in our system.' % new_email
assert_text_contains(get_element(id='box'), msg)

# confirm the new email was invalidated
helpers.login(email=new_email, password=DEFAULT_USER_PASSWORD)
wait_for(assert_title_contains, 'Log in')
msg = 'This email address has been invalidated. Please contact login support.'
assert_text_contains(get_element('span.error'), msg)
