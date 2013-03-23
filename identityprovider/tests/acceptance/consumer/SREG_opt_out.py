# FROM /consumer
# 3) Modify the data sent to the consumer (vary the data by checking/unchecking
# the ticks on the screen post login and ensure the data is not displayed)
# 4) Modify the level of requirement of data on the main consumer screen
# (change the radio buttons in the list from Require to any of the others)
# 6) Test you can see the sreg info from accessing the test consumer for a
# second time, ie 1st time nothing selected, 2nd time options selected are
# remembered
# 7) Test you can modify the second run to display different sreg info from
# the first

# CSV Rows.. the order of the rows is important, do not change unintentionally
# Row #1: tests that all sreg data is returned with required fields
# Row #2: tests that no sreg data is returned with optional fields toggled off
# Row #3: tests cookie remembers past choices for the website and presets,
#   also tests that mixed required fields and optional fields with opt-out that
#   correct data is returned

import ast

from django.conf import settings
from sst.actions import (
    assert_element,
    assert_title,
    assert_text,
    assert_text_contains,
    assert_title_contains,
    click_button,
    get_element,
    get_elements_by_xpath,
    go_to,
    set_radio_value,
    toggle_checkbox,
    wait_for,
    write_textfield,
)
from u1testutils.sst import config

from identityprovider.tests.acceptance.shared import urls
from identityprovider.tests.acceptance.shared.helpers import (
    skip_production,
)


config.set_base_url_from_env()
skip_production()

toggled_elements = ast.literal_eval(toggled_elements)
disabled_elements = ast.literal_eval(disabled_elements)
returned_sreg = ast.literal_eval(returned_sreg)

go_to(urls.CONSUMER)
wait_for(assert_title, 'Django OpenID Example Consumer')
toggle_checkbox('id_sreg')
set_radio_value(radio_nickname)
set_radio_value(radio_fullname)
set_radio_value(radio_email)
set_radio_value(radio_language)
click_button(get_element(value='Begin'))

wait_for(assert_title, 'Log in')
write_textfield('id_email', settings.QA_ACCOUNT_EMAIL)
write_textfield('id_password', settings.QA_ACCOUNT_PASSWORD)
click_button(get_element(name='continue'))

wait_for(assert_title_contains, 'Authenticate to')
# Check the elements specified in the .csv list
if toggled_elements is not None:
    for optional_sreg_element in toggled_elements:
        toggle_checkbox(optional_sreg_element)
if disabled_elements is not None:
    for required_sreg_element in disabled_elements:
        assert_element(id=required_sreg_element, disabled="disabled")
click_button(get_element(name='yes'))

wait_for(assert_title, 'Django OpenID Example Consumer')
assert_text_contains(get_element(tag='div', css_class='message success'),
                     'OpenID authentication succeeded')
count = 0

# Check correct sreg data was returned from the list in the .csv
if returned_sreg is not None:
    for sreg_element in returned_sreg:
        assert_text(get_elements_by_xpath("//li")[count], sreg_element)
        count = count + 1
