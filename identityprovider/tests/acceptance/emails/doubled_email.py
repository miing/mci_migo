from sst.actions import (
    assert_title,
    fails,
    wait_for,
)
from u1testutils import mail
from u1testutils.sst import config

from identityprovider.tests.acceptance.shared import helpers

config.set_base_url_from_env()
PASSWORD = 'Admin007'

# 2) Create 2 accounts (A & B).  In Account A add email address C and do not
# verify. In Account B add email address C and do not verify.
email_a_id = mail.make_unique_test_email_address()
email_b_id = mail.make_unique_test_email_address()
email_c_id = mail.make_unique_test_email_address()

helpers.register_account(email_a_id, password=PASSWORD)
vcode_x = helpers.add_email(email_c_id)

helpers.logout()

helpers.register_account(email_b_id, password=PASSWORD)
vcode_y = helpers.add_email(email_c_id)


# try x from a, should fail
helpers.logout()
helpers.login(email_a_id, PASSWORD)
# Trying and failing to use token X completely invalidates token X, even for
# account B (which now owns the token) later in this test.
# helpers.try_to_validate_email(email_c_id, vcode_x)
# fails(assert_title, 'Complete email address validation')

# try y from a, should fail
helpers.try_to_validate_email(email_c_id, vcode_y, finish_validation=False)
fails(assert_title, 'Complete email address validation')

# both x & y should work for b, but using one should kill the other.
# try x from b, should work
helpers.logout()
helpers.login(email_b_id, PASSWORD)
helpers.try_to_validate_email(email_c_id, vcode_x, finish_validation=False)
wait_for(assert_title, 'Complete email address validation')

# now, y from b should fail, because address C was already verified (but would
# normally work)
helpers.try_to_validate_email(email_c_id, vcode_y, finish_validation=False)
fails(assert_title, 'Complete email address validation')
