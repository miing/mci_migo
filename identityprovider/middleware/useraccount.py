# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from django.contrib.auth import logout
from django.contrib.auth.models import User

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

    def process_request(self, request):
        if request.user.is_authenticated():
            is_admin_url = self.is_admin_area(request.get_full_path())
            if isinstance(request.user, User) and not is_admin_url:
                try:
                    account = Account.objects.get(
                        openid_identifier=request.user.username)
                    request.user = account
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
