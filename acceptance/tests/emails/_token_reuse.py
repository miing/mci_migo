from sst.actions import (
    assert_title,
    fails,
)
from u1testutils import mail
from u1testutils.sst import config

from acceptance import helpers


config.set_base_url_from_env()

primary_email_id = mail.make_unique_test_email_address()
secondary_email_id = mail.make_unique_test_email_address()
print 'primary: %s\nsecondary: %s' % (primary_email_id, secondary_email_id)

helpers.register_account(primary_email_id)

#add email
vcode = helpers.add_email(secondary_email_id)
print 'vcode:', vcode

#delete it
helpers.delete_email()

#try to validate it
helpers.try_to_validate_email(secondary_email_id, vcode)

# ensure validation fails, and the e-mail address doesn't magically appear in
# our list
fails(assert_title, 'Complete email address validation')

#add same email
helpers.add_email(secondary_email_id)

#try to use the original validation token
helpers.try_to_validate_email(secondary_email_id, vcode)

#ensure it still fails
# XXX 2011-08-08 noodles bug=822733 We should not be able to complete
# the address validation, as the vcode is stale.
print('This step is failing due to '
      'https://bugs.launchpad.net/canonical-identity-provider/+bug/822733')
fails(assert_title, 'Complete email address validation')
