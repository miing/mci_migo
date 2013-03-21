from contextlib import contextmanager

from django.core.exceptions import ValidationError
from django.utils.translation import ugettext_lazy as _

from identityprovider.utils import (
    password_policy_compliant,
)


PASSWORD_POLICY_ERROR = _("Password must be at least 8 characters long.")
PASSWORD_POLICY_HELP_TEXT = PASSWORD_POLICY_ERROR


def validate_password_policy(password):
    """Validate password complies with policy."""
    try:
        str(password)
    except UnicodeEncodeError:
        raise ValidationError(_("Invalid characters in password"))
    if not password_policy_compliant(password):
        raise ValidationError(PASSWORD_POLICY_ERROR)


class Errors(dict):
    GENERAL = "__all__"

    @contextmanager
    def collect(self, key=None):
        try:
            yield
        except ValidationError as e:
            if key is not None:
                self[key] = e.messages
            else:
                # If you pass in an empty dict, django will overwrite the
                # reference to an ordinary dict. Srsly.
                self['Dont kill me, Django!'] = None
                e.update_error_dict(self)
                del self['Dont kill me, Django!']
