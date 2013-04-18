# FROM /consumer
# 1) Using the test consumer, Ensure that your team is displayed (Select teams
# add a team you are a member of)
# 2) Ensure that other teams are not displayed (Select teams add a team you are
# not a member of)
# Also tests multiple valid teams
# Also tests multiple teams where one of the teams is a private team where test
# user has no membership

import ast

from sst.actions import (
    assert_title,
    assert_text,
    assert_text_contains,
    click_button,
    get_element,
    get_elements_by_xpath,
    go_to,
    toggle_checkbox,
    wait_for,
    write_textfield,
)
from u1testutils.sst import config

from identityprovider.tests.acceptance.shared import urls
from identityprovider.tests.acceptance.shared.helpers import (
    is_staging,
    login_from_redirect,
    skip,
    skip_production,
)


config.set_base_url_from_env()
skip_production()

# XXX: skip if staging until the test can be made to reliably pass
if is_staging():
    skip()


resulting_teams = ast.literal_eval(resulting_teams)

go_to(urls.CONSUMER)
wait_for(assert_title, 'Django OpenID Example Consumer')

toggle_checkbox('id_teams')
write_textfield('id_request_teams', team_names)
click_button(get_element(value='Begin'))

login_from_redirect()

wait_for(assert_title, 'Django OpenID Example Consumer')
assert_text_contains(get_element(tag='div', css_class='message success'),
                     'OpenID authentication succeeded')

# Check the results of the team requests from the list in the .csv
for i, team in enumerate(resulting_teams):
    assert_text(get_elements_by_xpath("//li")[i], team)
