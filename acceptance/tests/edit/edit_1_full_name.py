# This test ensures that changing the full name for an account works.
from sst.actions import (
    assert_element,
    click_button,
    get_element,
    go_to,
    write_textfield,
)
from u1testutils.sst import config

from acceptance import helpers, urls


config.set_base_url_from_env()

# Create an account and login.
helpers.register_account(displayname="Fred Jones")

# Update the full name and verify the title change.
go_to(urls.EDIT)
write_textfield('id_displayname', 'Fred Jones Jnr')
click_button(get_element(name='update'))
assert_element(**{'data-qa-id': 'edit_account'})
