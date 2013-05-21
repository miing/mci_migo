# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from django.conf.urls import patterns, url

from piston.authentication import HttpBasicAuthentication
from piston.resource import Resource

from identityprovider.auth import (
    basic_authenticate,
    SSOOAuthAuthentication,
)

import api.v10.handlers as v10
import api.v11.handlers as v11
import api.v20.handlers as v20

from api.v20.utils import ApiOAuthAuthentication


v10root = Resource(handler=v10.RootHandler)
v10captcha = Resource(handler=v10.CaptchaHandler)
v10registration = Resource(handler=v10.RegistrationHandler)
v10auth = Resource(
    handler=v10.AuthenticationHandler,
    authentication=HttpBasicAuthentication(auth_func=basic_authenticate)
)
v10accounts = Resource(
    handler=v10.AccountsHandler,
    authentication=SSOOAuthAuthentication()
)


v11root = Resource(handler=v11.RootHandler)
v11auth = Resource(
    handler=v11.AuthenticationHandler,
    authentication=HttpBasicAuthentication(auth_func=basic_authenticate)
)


v2accounts = Resource(
    handler=v20.AccountsHandler, authentication=ApiOAuthAuthentication())
v2emails = Resource(handler=v20.EmailsHandler)
v2login = Resource(handler=v20.AccountLoginHandler)
v2login_phone = Resource(handler=v20.AccountPhoneLoginHandler)
v2registration = Resource(handler=v20.AccountRegistrationHandler)
v2requests = Resource(handler=v20.RequestsHandler)
v2password_reset = Resource(handler=v20.PasswordResetTokenHandler)

urlpatterns = patterns(
    '',
    # v1.0
    url(r'^1.0/$', v10root, name='api-10-root',
        kwargs={'emitter_format': 'lazr.restful'}),
    url(r'^1.0/captchas$', v10captcha, name='api-10-captchas',
        kwargs={'emitter_format': 'lazr.restful'}),
    url(r'^1.0/registration$', v10registration, name='api-10-registration',
        kwargs={'emitter_format': 'lazr.restful'}),
    url(r'^1.0/authentications$', v10auth, name='api-10-authentications',
        kwargs={'emitter_format': 'lazr.restful'}),
    url(r'^1.0/accounts$', v10accounts, name='api-10-accounts',
        kwargs={'emitter_format': 'lazr.restful'}),

    # v1.1
    url(r'^1.1/$', v11root,
        kwargs={'emitter_format': 'lazr.restful'}),
    # add backwards compatible endpoints
    url(r'^1.1/captchas$', v10captcha,
        kwargs={'emitter_format': 'lazr.restful'}),
    url(r'^1.1/registration$', v10registration,
        kwargs={'emitter_format': 'lazr.restful'}),
    url(r'^1.1/accounts$', v10accounts,
        kwargs={'emitter_format': 'lazr.restful'}),
    # add overriding endpoints
    url(r'^1.1/authentications$', v11auth,
        kwargs={'emitter_format': 'lazr.restful'}),

    # v2
    url(r'^v2/accounts$', v2registration, name='api-registration'),
    url(r'^v2/tokens/oauth$', v2login, name='api-login'),
    url(r'^v2/tokens/password$', v2password_reset, name='api-password-reset'),
    url(r'^v2/accounts/(\w+)$', v2accounts, name='api-account'),
    url(r'^v2/requests/validate$', v2requests, name='api-requests'),
    # login from phone, with a phone user id
    url(r'^v2/tokens/phone$', v2login_phone, name='api-login-phone'),
    # temporarily hooked up so we can do reverse()
    url(r'^v2/emails/(.*)$', v2emails, name='api-email'),
    url(r'^v2/tokens/oauth/(.*)$', v2login, name='api-token'),
    url(r'^v2/tokens/password/(.*)$', v2password_reset,
        name='api-password-reset'),
)
