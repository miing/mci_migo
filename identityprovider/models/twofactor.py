# Copyright 2010-2012 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

import logging
from datetime import datetime, timedelta

from oath.hotp import accept_hotp
from django.db import models
from django.conf import settings
from django.utils.translation import ugettext as _

from gargoyle import gargoyle

from identityprovider.models import Account


__all__ = ['AuthenticationDevice']
TWOFACTOR_LOGIN = 'two_factor_login'


def get_otp_type(otp):
    """Returns the format of otp, return None if not supported"""
    l = len(otp)
    if l == 6:
        return 'dec6'
    elif l == 8:
        return 'dec8'
    return None


def authenticate_device(account, otp):
    """Authenticates oath_token against the devices for an account."""
    for device in account.devices.order_by('-counter'):
        if device.authenticate(otp):
            return True
    # avoid circular import (identityprovider.login import
    # identityprovider.models which import from .twofactor import *
    from identityprovider.login import AuthenticationError
    raise AuthenticationError(_("The password is invalid"))


def is_twofactor_enabled(request):
    if settings.READ_ONLY_MODE:
        return False
    else:
        return gargoyle.is_active('TWOFACTOR', request)


def login(request):
    request.session[TWOFACTOR_LOGIN] = datetime.utcnow()


def logout(request):
    if TWOFACTOR_LOGIN in request.session:
        del request.session[TWOFACTOR_LOGIN]


def is_fresh(request):
    """Return True if the user's session was recently upgraded to 2-factor."""
    login = request.session.get(TWOFACTOR_LOGIN, None)
    if login is None:
        return False
    login = login + timedelta(0, settings.TWOFACTOR_FRESHNESS)
    return login >= datetime.utcnow()


def is_upgraded(request):
    """Return whether the user's session has been upgraded by a 2factor."""
    login = request.session.get(TWOFACTOR_LOGIN, None)
    if login is None:
        return False
    return login + timedelta(0, settings.TWOFACTOR_TTL) >= datetime.utcnow()


def is_authenticated(request):
    """Return whether the user is fully authenticated.

    According to his own 2nd-factor preference. This should be used as a
    replacement for request.user.is_authenticated() almost everywhere.
    """

    user = request.user

    if not user.is_authenticated():
        return False

    # User is at least 1st-factor authenticated
    if (is_twofactor_enabled(request) and user.twofactor_required):
        # and twofactor is enabled
        # and user requires 2nd factor.
        return is_upgraded(request)

    return True


def site_requires_twofactor_auth(request, token, rpconfig):
    if not is_twofactor_enabled(request):
        return False
    if rpconfig is not None and rpconfig.twofactor_required(request):
        return True
    # TODO: Check if site requested (through PAPE) 2f.
    return False


def user_requires_twofactor_auth(request, account):
    if not is_twofactor_enabled(request):
        return False
    if account.twofactor_required:
        if account.has_twofactor_devices():
            return True
        logging.warning('Account %s requires two-factor but has no devices' %
                        account.openid_identifier)
    return False


class AuthenticationDevice(models.Model):
    account = models.ForeignKey(Account, related_name='devices')
    key = models.TextField()
    name = models.TextField()
    counter = models.IntegerField(default=0)
    device_type = models.TextField(null=True)

    class Meta:
        app_label = 'identityprovider'
        # order devices by id by default
        ordering = ('id',)

    def authenticate(self, otp):
        """Authenticate the code against the device"""
        otp_type = get_otp_type(otp)
        if not otp_type:
            # avoid circular import (identityprovider.login import
            # identityprovider.models which import from .twofactor import *
            from identityprovider.login import AuthenticationError
            raise AuthenticationError(_("Invalid otp length, should be 6 or "
                                        "8 characters"))
        valid, new_counter = accept_hotp(
            self.key, otp, self.counter, otp_type, drift=settings.HOTP_DRIFT,
            backward_drift=settings.HOTP_BACKWARDS_DRIFT,
        )
        if valid:
            self.counter = new_counter
            self.save()
        return valid
