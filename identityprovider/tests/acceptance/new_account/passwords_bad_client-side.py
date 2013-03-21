#  password tests: client-side validation
#
#  rules:
#    Password must be at least 8 characters long.


from sst.actions import (
    assert_text,
    assert_title,
    assert_url,
    get_element,
    go_to,
    write_textfield,
)
from u1testutils.sst import config

import urls


config.set_base_url_from_env()

go_to(urls.NEW_ACCOUNT)
assert_url(urls.NEW_ACCOUNT)
assert_title('Create account')

elem = get_element(id='password_strength')

write_textfield('id_password', password)
assert_text(elem, error)
