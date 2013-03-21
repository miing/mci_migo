# Copyright 2010, 2012 Canonical Ltd.  This software is licensed under
# the GNU Affero General Public License version 3 (see the file
# LICENSE).

from django.utils.translation import ugettext as _


DETAILS_UPDATED = _("Your account details have been successfully updated")
DEVICE_ADDED = _("Authentication device '{name}' has been successfully added")
DEVICE_DELETED = _("Authentication device '{name}' has been successfully "
                   "deleted")
DEVICE_GENERATION_WARNING = _("Generating new codes will invalidate all the "
                              "existing codes.")
DEVICE_RENAMED = _("Authentication device '{original}' has been successfully "
                   "renamed to '{renamed}'")
EMAIL_DELETED = _("The email address {email} was deleted successfully")
OTP_MATCH_ERROR = _("The one-time password didn't match the OATH/HOTP key.")
TOKEN_DELETED = _("'{name}' token was revoked successfully")
VALIDATE_EMAIL = _("Validate your email address")
VALIDATE_EMAIL_DESC = _(
    "We&rsquo;ve just emailed {email_to} (from {email_from}) "
    "with instructions on validating your email address."
)
