# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from django.dispatch import Signal
from django.conf import settings
from django.contrib.auth.signals import user_logged_in
from django.db.models.signals import post_save

from oauth.oauth import OAuthRequest
from oauth_backend.models import Token

from identityprovider.const import SESSION_TOKEN_KEY, SESSION_TOKEN_NAME
from identityprovider.models import Account, AccountPassword
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


def invalidate_account_oauth_tokens(sender, instance, created, **kwargs):
    if not created:
        # invalidate oauth tokens on password change
        instance.account.invalidate_oauth_tokens()


post_save.connect(
    invalidate_account_oauth_tokens, sender=AccountPassword,
    dispatch_uid='identityprovider.AccountPassword.post_save')


def set_session_oauth_token(sender, user, request, **kwargs):
    # user is an Account instance here

    headers = {'Authorization': request.META.get('HTTP_AUTHORIZATION', '')}
    orequest = OAuthRequest.from_request(request.method, '', headers=headers)

    if orequest and 'oauth_token' in orequest.parameters:
        # check for token in headers (handle login_by_token case)
        token_key = orequest.get_parameter('oauth_token')
    elif settings.READ_ONLY_MODE:
        try:
            token_key = ''
            consumer_user = user.user
            if consumer_user is not None:
                # check for already existent token
                token = Token.objects.get(
                    name=SESSION_TOKEN_NAME, consumer__user=consumer_user)
                token_key = token.token
        except Token.DoesNotExist:
            # no token, this session will be invalidated when RO mode is off
            pass
    else:
        oauth_token, _ = user.get_or_create_oauth_token(
            token_name=SESSION_TOKEN_NAME)
        token_key = oauth_token.token

    request.session[SESSION_TOKEN_KEY] = token_key


# connect to user login when sender=Account
user_logged_in.connect(
    set_session_oauth_token, sender=Account,
    dispatch_uid='identityprovider.user_logged_in')
