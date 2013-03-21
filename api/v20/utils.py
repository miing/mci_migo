# Copyright 2010-2012 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).
from django.utils import simplejson as json

from django.utils.translation import ugettext as _
from django.http import HttpResponse
from django.core.urlresolvers import reverse

from identityprovider.auth import SSOOAuthAuthentication
from identityprovider.models.const import AccountStatus


def api_error(status, code, message, extra=None):
    data = {
        'code': code,
        'message': message,
        'extra': extra or {}
    }
    response = HttpResponse(content=data, status=status)
    response['Vary'] = 'Accept'
    return response


ERRORS = dict(
    INVALID_DATA=(400, _("Invalid request data")),

    CAPTCHA_REQUIRED=(
        401, _('A captcha challenge is required to complete the request.')),
    INVALID_CREDENTIALS=(401, _('Provided email/password is not correct.')),
    TWOFACTOR_REQUIRED=(401, _("2-factor authentication required.")),

    ACCOUNT_SUSPENDED=(
        403, _('Your account has been suspended. Please contact login '
               'support to re-enable it')),
    ACCOUNT_DEACTIVATED=(
        403, _('Your account has been deactivated. To reactivate it, '
               'please reset your password')),
    EMAIL_INVALIDATED=(
        403, _("This email address has been invalidated. Please contact "
               "login support.")),
    CAN_NOT_RESET_PASSWORD=(403, _('Can not reset password. Please contact '
                                   'login support')),
    CAPTCHA_FAILURE=(403, _('Failed response to captcha challenge.')),
    TOO_MANY_TOKENS=(403, _('Too many non-consumed tokens exist. Further '
                            'token creation is not allowed until existing '
                            'tokens are consumed.')),
    TWOFACTOR_FAILURE=(
        403, _("The provided 2-factor key is not recognised.")),

    RESOURCE_NOT_FOUND=(404, _("The resource requested was not found.")),

    ALREADY_REGISTERED=(409, _("The email address is already registered")),
)


class Errors(object):
    def wrap(self, code):
        status, message = ERRORS[code]

        def wrapper(**extra):
            return api_error(status, code, message, extra)
        wrapper.__name__ = code
        return wrapper

    def __getattr__(self, attr):
        if attr in ERRORS:
            return self.wrap(attr)
        else:
            raise AttributeError

errors = Errors()


def _get_account_status_text(status):
    return unicode(AccountStatus._verbose[status])


def get_minimal_account_data(account):
    """Returns the minimal non-private data for the account."""
    href = reverse('api-account', args=(account.openid_identifier,))
    data = dict(
        href=href,
        openid=account.openid_identifier,
        verified=account.is_verified,
    )
    return data


def get_account_data(account):
    """Get the relevant data from an account to be serialized."""
    data = get_minimal_account_data(account)
    email = None
    if account.preferredemail is not None:
        email = account.preferredemail.email
    data.update(
        email=email,
        displayname=account.displayname,
        status=_get_account_status_text(account.status),
        emails=[
            dict(href=reverse('api-email', args=(email.email,)))
            for email in account.emailaddress_set.all()
        ]
    )
    return data


class ApiOAuthAuthentication(SSOOAuthAuthentication):
    def challenge(self):
        """Returns a json body 401 response"""
        response = errors.INVALID_CREDENTIALS()
        response.content = json.dumps(response._container)
        response['content-type'] = 'application/json; charset=utf-8'
        # set headers
        # urgh - hardcoded realm - but piston has it hardcoded...
        for k, v in self.builder(realm='API').iteritems():
            response[k] = v
        return response
