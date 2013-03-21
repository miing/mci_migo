# Copyright 2010-2012 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from identityprovider.models import (
    EmailAddress,
    Account,
)
from identityprovider.emailutils import (
    send_impersonation_email,
    send_new_user_email,
)
from identityprovider.signals import account_created


class EmailAlreadyRegistered(Exception):
    pass


def register(email, password, displayname):
    """Register a new account"""
    emails = EmailAddress.objects.filter(email__iexact=email)
    if emails.count() > 0:
        other_email = emails[0]
        # Only send email if the account is active; otherwise, a disabled
        # account can be spammed.
        if other_email.account.is_active:
            send_impersonation_email(other_email.email)
        raise EmailAlreadyRegistered(email)

    account = Account.objects.create_account(
        displayname,
        email,
        password,
        email_validated=False,
    )

    account_created.send('api', openid_identifier=account.openid_identifier)

    send_new_user_email(account=account, email=email)

    return account
