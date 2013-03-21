# Copyright 2010-2012 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).
import logging
from django.utils import simplejson as json

from datetime import datetime, timedelta

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.serializers.json import DateTimeAwareJSONEncoder
from django.http import (
    HttpResponseBadRequest,
    HttpResponseForbidden,
)
from django.shortcuts import render_to_response
from piston.emitters import Emitter
from piston.handler import BaseHandler

from identityprovider import emailutils
from identityprovider.models import (
    EmailAddress,
    Account,
    AuthToken,
)
from identityprovider.models.const import (
    EmailStatus,
    TokenType,
)
from identityprovider.models.captcha import (
    Captcha,
    NewCaptchaError,
    VerifyCaptchaError,
)
from identityprovider.models.team import get_team_memberships_for_user
from identityprovider.signals import (
    account_created,
    account_email_validated,
    application_token_created,
    application_token_invalidated,
)
from identityprovider.validators import validate_password_policy

from oauth_backend.models import Token

from api.v10.decorators import (
    api_user_required,
    plain_user_required,
    named_operation,
)
from api.v10.forms import (
    WebserviceCreateAccountForm,
)


def api_error(cls, msg):
    """Ensure 4xx response content in plain text to avoid XSS"""
    return cls(msg, content_type='text/plain')


class LazrRestfulEmitter(Emitter):
    """JSON emitter, lazr.restful flavoured.

    Reports content-type 'application/json', without specifying a charset
    as that seems to confuse lazr.restfulclient.
    """
    def render(self, request):
        # ensure_ascii=False was causing bug #820216
        # it looks like this is because simplejson's implementation is
        # broken
        # http://code.google.com/p/simplejson/issues/detail?id=48
        # https://code.djangoproject.com/ticket/6234
        seria = json.dumps(self.construct(),
                           cls=DateTimeAwareJSONEncoder, indent=4)

        return seria
Emitter.register('lazr.restful', LazrRestfulEmitter, 'application/json')


class LazrRestfulHandler(BaseHandler):
    allowed_methods = ('GET', 'POST')

    response = {}

    baseurl = settings.SSO_ROOT_URL.strip('/')

    def __init__(self):
        self.response = self.response.copy()
        for key, value in self.response.items():
            if key.endswith('_link'):
                self.response[key] = value % self.baseurl

    def read(self, request):
        if not 'ws.op' in request.GET:
            return self.response
        return self.named_operation(request, request.GET)

    def create(self, request):
        if not 'ws.op' in request.POST:
            return api_error(HttpResponseBadRequest,
                             'No operation name given.')
        return self.named_operation(request, request.POST)

    def named_operation(self, request, serialized):
        method_name = serialized['ws.op']
        method = getattr(self, method_name, None)
        is_named_operation = getattr(method, 'is_named_operation', False)
        if not is_named_operation:
            return api_error(HttpResponseBadRequest,
                             'No such operation: %s' % method_name)
        request.data = self.lazr_restful_deserialize(serialized)
        return method(request)

    def lazr_restful_deserialize(self, serialized):
        data = {}
        for key in serialized:
            if key == 'ws.op':
                continue
            try:
                value = json.loads(serialized[key])
            except (ValueError, TypeError):
                value = serialized[key]
            data[key] = value
        return data


class RootHandler(LazrRestfulHandler):
    allowed_methods = ('GET',)

    response = {
        "registrations_collection_link": "%s/api/1.0/registration",
        "captchas_collection_link": "%s/api/1.0/captchas",
        "validations_collection_link": "%s/api/1.0/validation",
        "authentications_collection_link": "%s/api/1.0/authentications",
        "resource_type_link": "%s/api/1.0/#service-root",
        "accounts_collection_link": "%s/api/1.0/accounts",
    }

    wadl_template = 'api/wadl1.0.xml'

    def read(self, request):
        if ('application/vd.sun.wadl+xml' in request.META['HTTP_ACCEPT'] or
                'application/vnd.sun.wadl+xml' in request.META['HTTP_ACCEPT']):
            context = {'baseurl': self.baseurl}
            return render_to_response(self.wadl_template, context)
        else:
            return self.response


class CaptchaHandler(LazrRestfulHandler):
    response = {
        "total_size": 0,
        "start": None,
        "resource_type_link": "%s/api/1.0/#captchas",
        "entries": []
    }

    @named_operation
    def new(self, request):
        try:
            return Captcha.new().serialize()
        except NewCaptchaError, e:
            logging.exception("Failed to connect to reCaptcha server")
            # TODO: Some better return here?
            return e.dummy


class RegistrationHandler(LazrRestfulHandler):
    response = {
        "total_size": 0,
        "start": None,
        "resource_type_link": "%s/api/1.0/#registrations",
        "entries": []
    }

    @named_operation
    def register(self, request):
        data = request.data
        data['remote_ip'] = request.environ['REMOTE_ADDR']
        form = WebserviceCreateAccountForm(data)
        try:
            if not form.is_valid():
                errors = dict((k, map(unicode, v))
                              for (k, v) in form.errors.items())
                result = {'status': 'error', 'errors': errors}
                return result
        except VerifyCaptchaError:
            logging.exception("reCaptcha connection error")
            msg = 'Unable to verify captcha. Please try again shortly.'
            return {
                'status': 'error',
                'errors': {'captcha_solution': [msg]}
            }

        cleaned_data = form.cleaned_data
        requested_email = cleaned_data['email']
        emails = EmailAddress.objects.filter(email__iexact=requested_email)
        if len(emails) > 0:
            return {'status': 'error',
                    'errors': {'email': ['Email already registered']}}

        platform = cleaned_data['platform']
        redirection_url = cleaned_data['validate_redirect_to']
        password = cleaned_data['password']
        displayname = cleaned_data['displayname']
        email = cleaned_data['email']
        if platform in ['desktop', 'mobile']:
            account = Account.objects.create_account(
                displayname, email, password, email_validated=False)
            encrypted_password = account.encrypted_password

        if platform == 'desktop':
            emailutils.send_new_user_email(
                account, email, redirection_url, platform)
        else:  # web or mobile, ensured by the form validators
            assert platform in ('web', 'mobile')
            emailutils.send_new_user_email(
                None, email, redirection_url, platform,
                displayname=displayname, password=encrypted_password)

        if account is not None:
            account_created.send(sender=self,
                                 openid_identifier=account.openid_identifier)

        return {
            'status': 'ok',
            'message': "Email verification required."
        }

    @named_operation
    def request_password_reset_token(self, request):
        data = request.data
        email = data['email']

        account = Account.objects.get_by_email(email)
        if account is None or not account.can_reset_password:
            return api_error(HttpResponseForbidden,
                             "CanNotResetPasswordError: Can't reset password "
                             "for this account.")

        emailutils.send_password_reset_email(account, email)

        return {
            'status': 'ok',
            'message': "Password reset token sent."
        }

    @named_operation
    def set_new_password(self, request):
        data = request.data
        new_password = data['new_password']
        try:
            # XXX: should also check that date_consumed=None! (nessita)
            token = AuthToken.objects.get(
                email=data['email'], token=data['token'],
                token_type=TokenType.PASSWORDRECOVERY)
        except AuthToken.DoesNotExist:
            return api_error(HttpResponseForbidden,
                             "CanNotSetPasswordError: Invalid token.")
        if not token.requester:
            token.delete()
            return {
                'status': 'error',
                'message': "Wrong token, request new one."
            }

        try:
            validate_password_policy(new_password)
        except ValidationError, e:
            return {
                'status': 'error',
                'errors': e.messages,
            }
        token.requester.set_password(new_password)
        token.consume()

        return {
            'status': 'ok',
            'message': "Password changed"
        }


def _serialize_account(user):
    emails = EmailAddress.objects.filter(account=user,
                                         status=EmailStatus.VALIDATED)
    preferred_email = user.preferredemail
    if preferred_email is not None:
        preferred_email = preferred_email.email

    if user.person:
        username = user.person.name
    else:
        username = user.openid_identifier

    return {
        'username': username,
        'displayname': user.displayname,
        'openid_identifier': user.openid_identifier,
        'preferred_email': preferred_email,
        'verified_emails': [e.email for e in emails],
        'unverified_emails': [e.email for e in user.unverified_emails()],
    }


class AuthenticationHandler(LazrRestfulHandler):
    """All these methods assume that they're run behind Basic Auth."""
    response = {
        "total_size": 0,
        "start": None,
        "resource_type_link": "%s/api/1.0/#authentications",
        "entries": []
    }

    @plain_user_required
    @named_operation
    def authenticate(self, request):
        data = request.data
        account = request.user
        token = account.create_oauth_token(data['token_name'])
        application_token_created.send(
            sender=self, openid_identifier=account.openid_identifier)
        return token.serialize()

    @api_user_required
    @named_operation
    def list_tokens(self, request):
        data = request.data
        tokens = Token.objects.filter(
            consumer__user__username=data['consumer_key'])
        result = [{'token': t.token, 'name': t.name} for t in tokens]
        return result

    @api_user_required
    @named_operation
    def validate_token(self, request):
        data = request.data
        token = data.get('token')
        openid = data.get('consumer_key')
        max_age = data.get('max_age')

        try:
            token = Token.objects.get(
                consumer__user__username=openid,
                token=token)
        except Token.DoesNotExist:
            return False

        if max_age is not None:
            # we use datetime.now() here (instead of utcnow, because the token
            # stores it's updated_at timestamp in localtime)
            age = datetime.now() - token.updated_at
            if age > timedelta(seconds=max_age):
                # token is too old
                return False
        return token.serialize()

    @api_user_required
    @named_operation
    def invalidate_token(self, request):
        data = request.data
        tokens = Token.objects.filter(
            token=data['token'], consumer__user__username=data['consumer_key'])
        tokens.delete()
        application_token_invalidated.send(
            sender=self, openid_identifier=data['consumer_key'])

    @api_user_required
    @named_operation
    def team_memberships(self, request):
        data = request.data
        accounts = Account.objects.filter(
            openid_identifier=data['openid_identifier'])
        accounts = list(accounts)

        if len(accounts) == 1:
            account = accounts[0]
            memberships = (
                get_team_memberships_for_user(
                    data['team_names'], account, include_private=True))
            return memberships
        else:
            return []

    @api_user_required
    @named_operation
    def account_by_email(self, request):
        data = request.data
        account = Account.objects.get_by_email(data['email'])
        if account:
            return _serialize_account(account)
        else:
            return None

    @api_user_required
    @named_operation
    def account_by_openid(self, request):
        data = request.data
        try:
            account = Account.objects.get(openid_identifier=data['openid'])
        except Account.DoesNotExist:
            return None
        else:
            return _serialize_account(account)


class AccountsHandler(LazrRestfulHandler):
    @named_operation
    def me(self, request):
        account = request.user
        return _serialize_account(account)

    @named_operation
    def team_memberships(self, request):
        team_names = request.data['team_names']

        memberships = (
            get_team_memberships_for_user(
                team_names, request.user, include_private=True))
        return memberships

    @named_operation
    def validate_email(self, request):
        email_token = request.data['email_token']
        try:
            # XXX: should also check that date_consumed=None! (nessita)
            # And that the email in the authtoken is the same as the
            # email being validated
            token = request.user.authtoken_set.get(
                token=email_token, token_type=TokenType.VALIDATEEMAIL)

            email = EmailAddress.objects.get(email__iexact=token.email)
            email.status = EmailStatus.VALIDATED
            email.save()

            token.consume()

            account_email_validated.send(
                openid_identifier=request.user.openid_identifier,
                sender=self)
            return {'email': email.email}
        except AuthToken.DoesNotExist:
            return {'errors': {'email_token': ["Bad email token!"]}}
