# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from datetime import datetime
from django.http import HttpResponse

from oauth_backend.models import Consumer, Token
from piston.authentication import OAuthAuthentication

from identityprovider.models import Account, AccountPassword
from identityprovider.models.api import APIUser
from identityprovider.models.const import EmailStatus
from identityprovider.utils import (
    validate_launchpad_password, get_object_or_none)


class LaunchpadBackend(object):

    valid_email_statuses = (
        EmailStatus.PREFERRED, EmailStatus.VALIDATED, EmailStatus.NEW)

    def authenticate(self, username=None, password=None,
                     encrypted_password=None, token=None):
        if token:
            account = self.authenticate_by_token(token)
        else:
            account = self.authenticate_by_username(username, password,
                                                    encrypted_password)
        if account:
            # we use now() here because last_login maps to django's auth model
            # which uses localtime.
            account.last_login = datetime.now()
        return account

    def authenticate_by_username(self, username=None, password=None,
                                 encrypted_password=None):
        try:
            account = Account.objects.select_related('accountpassword')
            account = account.get(
                emailaddress__email__iexact=username,
                emailaddress__status__in=self.valid_email_statuses)
        except Account.DoesNotExist:
            return None
        if not account.is_active:
            return None

        try:
            ap = account.accountpassword
            if ap is None:
                return None
        except AccountPassword.DoesNotExist:
            # password lost somehow, user should reset it
            return None

        try:
            if password is not None:
                if not validate_launchpad_password(password, ap.password):
                    return None
            elif encrypted_password is not None:
                if encrypted_password != ap.password:
                    return None
            else:
                return None
        except (UnicodeDecodeError, UnicodeEncodeError):
            # Password not ASCII, we must fail
            return None
        return account

    def authenticate_by_token(self, token):
        user = token.consumer.user
        try:
            account = Account.objects.get(openid_identifier=user.username)
        except Account.DoesNotExist:
            return None
        if not account.is_active:
            return None
        return account

    def get_user(self, user_id):
        """Returns a Launchpad Account object instead of Django's built-in
        User object. """
        return get_object_or_none(Account.objects.select_related(), pk=user_id)

    def supports_anonymous_user(self):
        return False

    def supports_object_permissions(self):
        return False


def basic_authenticate(username, password):
    """Function used by lazr.authentication middleware"""
    api_user = APIUser.authenticate(username, password)
    if api_user is not None:
        return api_user
    user = LaunchpadBackend().authenticate(username, password)
    return user


class SSOOAuthAuthentication(OAuthAuthentication):
    """Custom class to perform OAuth authentication.

    Besides what the OAuthAuthentication class checks for authenticaion,
    confirm that the consumer belongs to an SSO active Account.
    """

    def is_authenticated(self, request):
        if super(SSOOAuthAuthentication, self).is_authenticated(request):
            # only allow authentication if account is active
            openid = request.user.oauth_consumer.key
            account = Account.objects.active_by_openid(openid)
            if account is not None:
                request.user = account
                return True
            del request.user

        return False

    def challenge(self):
        resp = HttpResponse("Authorization Required")
        resp['WWW-Authenticate'] = 'OAuth realm="%s"' % self.realm
        resp.status_code = 401
        return resp


def oauth_authenticate(oauth_consumer, oauth_token, parameters):
    """Currently only checks that given consumer and token are in database"""
    try:
        consumer = Consumer.objects.get(
            user__username=oauth_consumer.key)
        token = Token.objects.get(token=oauth_token.key)

    except (Token.DoesNotExist, Consumer.DoesNotExist):
        return None
    else:
        # only allow authentication if account is active
        account = Account.objects.get(openid_identifier=consumer.key)
        if not account.is_active:
            return None

        if token.consumer.key == oauth_consumer.key:
            return account
        else:
            return None
