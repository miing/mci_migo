#  password tests: server-side validation
#
# rules:
#   Password must be at least 8 characters long.

from sst.actions import (
    assert_element,
    assert_text,
    click_button,
    fails,
    get_element,
    get_elements,
    wait_for,
    write_textfield,
)
from u1testutils import mail
from u1testutils.sst import config

from acceptance import helpers


config.set_base_url_from_env()

email_id = mail.make_unique_test_email_address()
vcode = helpers.register_account(email_id)
# helpers.try_to_validate_email(email_id, vcode)
edit_account_anchor = {'data-qa-id': 'edit_account'}

wait_for(assert_element, **edit_account_anchor)

print 'password: %s\nconfirm: %s' % (password, passwordconfirm)

write_textfield('id_password', password)
write_textfield('id_passwordconfirm', passwordconfirm)
click_button(get_element(name='update'))
wait_for(assert_element, **edit_account_anchor)

if error == 'bad':
    bad_msg = 'Password must be at least 8 characters long.'
    assert_text(get_element(css_class='error'), bad_msg)
elif error == 'mismatch':
    mismatch_msg = "Passwords didn't match"
    assert_text(get_element(css_class='error'), mismatch_msg)
elif error == 'good':
    fails(get_elements, css_class='error')
else:
    print 'Unknown error type "%s"' % error
    assert False
