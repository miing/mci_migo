# 10) Check that missing values do not allow submission of the 'email
# verification' form.'

from sst.actions import (
    assert_text_contains,
    assert_title,
    fails,
    go_to,
    wait_for,
)
from u1testutils.sst import config

from acceptance import helpers, urls


config.set_base_url_from_env()

# No account required, so jump straight to the form.
go_to(urls.ENTER_TOKEN)
wait_for(assert_title, 'Enter confirmation code')

helpers.try_to_validate_email(address, code, finish_validation=False)
wait_for(assert_title, 'Enter confirmation code')

error1_msg = 'This field is required.'
error2_msg = 'Required field.'

if error1:
    assert_text_contains('content', error1_msg)
else:
    fails(assert_text_contains, 'content', error1_msg)

if error2:
    assert_text_contains('content', error2_msg)
else:
    fails(assert_text_contains, 'content', error2_msg)
