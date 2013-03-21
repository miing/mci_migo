# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from django.dispatch import Signal
from django.conf import settings
from identityprovider.utils import http_request_with_timeout


account_created = Signal(providing_args=["openid_identifier"])
account_details_changed = Signal(providing_args=["openid_identifier"])
account_email_added = Signal(providing_args=["openid_identifier"])
account_email_validated = Signal(providing_args=["openid_identifier"])

application_token_created = Signal(providing_args=["openid_identifier"])
application_token_invalidated = Signal(providing_args=["openid_identifier"])


def account_change_notify(sender, openid_identifier, **kwargs):
    update_url = getattr(settings, "SSO_ACCOUNT_UPDATE_URL")
    if update_url:
        http_request_with_timeout(update_url,
                                  {"openid_identifier": openid_identifier})


# Wire up all signals with notification function
account_created.connect(account_change_notify)
account_details_changed.connect(account_change_notify)
account_email_added.connect(account_change_notify)
account_email_validated.connect(account_change_notify)
application_token_created.connect(account_change_notify)
application_token_invalidated.connect(account_change_notify)
