# Copyright 2010-2013 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).
from django.contrib import auth
from django.utils.translation import ugettext as _
from gargoyle import gargoyle

from identityprovider.models import Account, InvalidatedEmailAddress
from identityprovider.models.const import (
    AccountStatus,
    EmailStatus,
)


class AuthenticationError(Exception):
    pass


class AccountSuspended(AuthenticationError):
    pass


class AccountDeactivated(AuthenticationError):
    pass


class EmailInvalidated(AuthenticationError):
    pass


def is_unverified_account_allowed(account, rpconfig):
    if rpconfig is not None:
        return rpconfig.allow_unverified
    else:
        return gargoyle.is_active('ALLOW_UNVERIFIED', account)


def authenticate_user(email, password, rpconfig=None):
    """Attempts to authenticate a user. Returns account on success, or throws
    AuthenticationErrors on failure"""
    account = auth.authenticate(username=email, password=password)

    if account is None:
        # further specific error messages for the user
        account = Account.objects.get_by_email(email)
        if account is not None:
            email_obj = account.emailaddress_set.get(email__iexact=email)

            if not account.is_active:
                if account.status == AccountStatus.SUSPENDED:
                    raise AccountSuspended(
                        _('Your account has been suspended. Please contact '
                          'login support to re-enable it'))
                else:
                    raise AccountDeactivated(
                        _('Your account has been deactivated. To reactivate '
                          'it, please reset your password'))
        else:
            # check if this is an invalidated email address
            invalidated = InvalidatedEmailAddress.objects.filter(
                email__iexact=email)
            if invalidated.exists():
                raise EmailInvalidated(
                    _("This email address has been invalidated. "
                      "Please contact login support."))

        raise AuthenticationError(_("Password didn't match."))

    # if LOGIN_BY_PHONE is enabled for this account, just return it
    # since LOGIN_BY_PHONE assumes ALLOW_UNVERIFIED
    if gargoyle.is_active('LOGIN_BY_PHONE', account):
        return account

    if is_unverified_account_allowed(account, rpconfig):
        return account

    email_obj = account.emailaddress_set.get(email__iexact=email)
    if email_obj.status == EmailStatus.NEW:
        raise AuthenticationError(_("Password didn't match."))

    return account
