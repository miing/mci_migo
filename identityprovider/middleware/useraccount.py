# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from django.conf import settings
from django.contrib.auth import logout
from django.contrib.auth.models import User

from oauth_backend.models import Token

from identityprovider.const import SESSION_TOKEN_KEY
from identityprovider.models import Account


class UserAccountConversionMiddleware(object):
    """Try to convert request.user to the corresponding Account objects.

    If it's a User object, and the request is outside of the admin, and vice
    versa.

    If it cannot do the conversion, simply log out the user from
    the session.
    """

    def is_admin_area(self, url):
        return (url.startswith('/admin/') or url.startswith('/readonly') or
                url == '/assets/identityprovider/admin-fixes.css' or
                url.startswith('/nexus/'))

    def _validate_session(self, request, account):
        oauth_token = request.session.get(SESSION_TOKEN_KEY, None)

        if settings.READ_ONLY_MODE and oauth_token == '':
            # this is a session created during RO mode, skip
            return

        if oauth_token is None:
            # this will invalidate/log out all previous existent sessions
            logout(request)
        else:
            # validate session with given account/token
            # hit the db only if we have to (ie, there is a token key to check)
            try:
                account.oauth_tokens().get(token=oauth_token)
            except Token.DoesNotExist:
                logout(request)

    def process_request(self, request):
        if request.user.is_authenticated():
            is_admin_url = self.is_admin_area(request.get_full_path())
            if isinstance(request.user, User) and not is_admin_url:
                try:
                    account = Account.objects.get(
                        openid_identifier=request.user.username)
                    request.user = account
                    self._validate_session(request, account)
                except Account.DoesNotExist:
                    logout(request)
            elif isinstance(request.user, Account) and is_admin_url:
                try:
                    user = User.objects.get(
                        username=request.user.openid_identifier)
                    request.user = user
                except User.DoesNotExist:
                    logout(request)
            if isinstance(request.user, Account):
                lang = request.user.preferredlanguage
                if lang is not None:
                    request.session['django_language'] = lang
                self._validate_session(request, request.user)
