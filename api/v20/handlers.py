# Copyright 2010-2012 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).
import logging

from django.core.exceptions import ValidationError
from django.core.urlresolvers import reverse
from django.conf import settings
from gargoyle import gargoyle
from oauth import oauth
from piston.handler import AnonymousBaseHandler, BaseHandler
from piston.utils import require_mime

from api.v20 import registration
from api.v20.utils import (
    errors,
    get_account_data,
    get_minimal_account_data,
    rc
)
from identityprovider import emailutils
from identityprovider.login import (
    AccountDeactivated,
    AccountSuspended,
    AuthenticationError,
    authenticate_user,
    EmailInvalidated,
)
from identityprovider.models import (
    Account,
    AuthToken,
    EmailAddress,
    InvalidatedEmailAddress,
    twofactor,
)
from identityprovider.models.captcha import Captcha, VerifyCaptchaError
from identityprovider.models.const import (
    AccountStatus,
    TokenType,
)
from identityprovider.utils import redirection_url_for_token
from identityprovider.store import SSODataStore


logger = logging.getLogger('sso')


class AnonymousAccountsHandler(AnonymousBaseHandler):
    allowed_methods = ('GET',)

    def read(self, request, openid):
        account = Account.objects.active_by_openid(openid)
        if account is None:
            return errors.RESOURCE_NOT_FOUND()

        return get_minimal_account_data(account)


class AccountsHandler(BaseHandler):
    allowed_methods = ('GET',)
    anonymous = AnonymousAccountsHandler

    def read(self, request, openid):
        """Return account information."""
        if request.user.openid_identifier != openid:
            return errors.RESOURCE_NOT_FOUND()

        return get_account_data(request.user)


class PasswordResetTokenHandler(BaseHandler):
    allowed_methods = ('POST',)

    @require_mime('json')
    def create(self, request):
        data = request.data
        email = data.get('email')
        if email is None:
            return errors.INVALID_DATA(email='Field required')

        token = data.get('token')

        account = Account.objects.get_by_email(email)
        invalidated_email = InvalidatedEmailAddress.objects.filter(
            email__iexact=email)

        if account is None:
            # they've tried to reset with an invalid email, so send them
            # an email on how to create an account
            emailutils.send_invitation_after_password_reset(email)

            if invalidated_email.exists():
                # there is no account with this email
                # but there was some with it invalidated
                return errors.EMAIL_INVALIDATED()
            else:
                # there is no account, neither with this email invalidated
                return errors.INVALID_DATA(
                    email="No account associated with %s" % email)

        if not account.can_reset_password:
            if account.status == AccountStatus.SUSPENDED:
                # log why email was not sent
                condition = ("account '%s' is not active" %
                             account.displayname)
                logger.debug("PasswordResetTokenHandler.create: email was "
                             "not sent out because %s" % condition)
                return errors.ACCOUNT_SUSPENDED()
            elif account.status == AccountStatus.DEACTIVATED:
                # log why email was not sent
                condition = ("account '%s' is not active" %
                             account.displayname)
                logger.debug("PasswordResetTokenHandler.create: email was "
                             "not sent out because %s" % condition)
                return errors.ACCOUNT_DEACTIVATED()

            # user does not have any verified email address
            # he should contact support
            condition = ("account '%s' is not allowed to reset password" %
                         account.displayname)
            logger.debug("PasswordResetTokenHandler.create: email was not "
                         "sent out because %s" % condition)
            return errors.CAN_NOT_RESET_PASSWORD()

        if account.preferredemail is not None:
            email = account.preferredemail.email

        tokens = AuthToken.objects.filter(
            token_type=TokenType.PASSWORDRECOVERY, requester_email=email,
            email=email, date_consumed=None)
        if tokens.count() >= settings.MAX_PASSWORD_RESET_TOKENS:
            return errors.TOO_MANY_TOKENS()

        # create new token and send email to user
        redirection_url = redirection_url_for_token(token)
        token = emailutils.send_password_reset_email(
            account, email, redirection_url)

        # return response
        data = dict(email=token.email)
        response = rc.CREATED
        response.content = data
        return response


class AccountRegistrationHandler(BaseHandler):
    allowed_methods = ('POST',)

    @require_mime('json')
    def create(self, request):
        """Create/register a new account."""
        data = request.data
        captcha_id = data.get('captcha_id')
        captcha_solution = data.get('captcha_solution')
        if (not (captcha_solution and captcha_id) and
                gargoyle.is_active('CAPTCHA')):
            extra = {}
            if data.get('create_captcha', True):
                try:
                    extra = Captcha.new().serialize()
                except Exception:
                    logging.exception('failed to create reCaptcha')
            return errors.CAPTCHA_REQUIRED(**extra)

        elif captcha_id:
            remote_addr = request.environ['REMOTE_ADDR']
            captcha = Captcha(captcha_id)
            verified = False
            try:
                verified = captcha.verify(
                    captcha_solution, remote_addr, data['email'])
            except VerifyCaptchaError:
                logging.exception("reCaptcha connection error")
            except Exception:
                logging.exception("reCaptcha network error")
            if not verified:
                message = getattr(captcha, 'message', '')
                return errors.CAPTCHA_FAILURE(captcha_message=message)

        try:
            account = registration.register(
                data.get('email'),
                data.get('password'),
                data.get('displayname'),
            )
        except ValidationError as e:
            return errors.INVALID_DATA(**e.message_dict)
        except registration.EmailAlreadyRegistered:
            return errors.ALREADY_REGISTERED(email=data['email'])

        data = get_account_data(account)
        response = rc.CREATED
        response.content = data
        return response


class AccountLoginHandler(BaseHandler):
    allowed_methods = ('POST', )

    @require_mime('json')
    def create(self, request):
        data = request.data

        try:
            email = data['email']
            password = data['password']
            token_name = data['token_name']
        except KeyError:
            expected = set(('email', 'password', 'token_name'))
            missing = dict((k, 'Field required') for k in expected - set(data))
            return errors.INVALID_DATA(**missing)

        try:
            account = authenticate_user(email, password)
        except AccountSuspended:
            return errors.ACCOUNT_SUSPENDED()
        except AccountDeactivated:
            return errors.ACCOUNT_DEACTIVATED()
        except EmailInvalidated:
            return errors.EMAIL_INVALIDATED()
        except AuthenticationError:
            return errors.INVALID_CREDENTIALS()

        otp = data.get('otp')
        if otp is not None:
            try:
                twofactor.authenticate_device(account, otp)
            except AuthenticationError:
                return errors.TWOFACTOR_FAILURE()
        elif account.twofactor_required:
            return errors.TWOFACTOR_REQUIRED()

        token, created = account.get_or_create_oauth_token(token_name)
        if created:
            response = rc.CREATED
        else:
            response = rc.ALL_OK
        response.content = {
            "consumer_key": token.consumer.key,
            "consumer_secret": token.consumer.secret,
            "token_key": token.token,
            "token_secret": token.token_secret,
            "token_name": token_name,
            "date_created": token.created_at,
            "date_updated": token.updated_at,
            "href": reverse('api-token', args=(token.token,)),
            "openid": account.openid_identifier,
        }
        return response


class AccountPhoneLoginHandler(BaseHandler):
    allowed_methods = ('POST', )

    @require_mime('json')
    def create(self, request):
        data = request.data
        # email should be available the first time, to bind account/phone
        # after that, get email from phoneid in the token name
        email = data.get('email')
        try:
            phone_id = data['phone_id']
            password = data['password']
            token_name = data['token_name']
        except KeyError:
            expected = set(('phone_id', 'password', 'token_name'))
            missing = dict((k, 'Field required') for k in expected - set(data))
            return errors.INVALID_DATA(**missing)

        try:
            phone_email = EmailAddress.objects.get_from_phone_id(phone_id)
            login_email = phone_email.email
        except EmailAddress.DoesNotExist:
            phone_email = None
            login_email = email

        if login_email is None:
            return errors.INVALID_DATA(phone_id='invalid value')

        try:
            account = authenticate_user(login_email, password)
        except AccountSuspended:
            return errors.ACCOUNT_SUSPENDED()
        except AccountDeactivated:
            return errors.ACCOUNT_DEACTIVATED()
        except AuthenticationError:
            return errors.INVALID_CREDENTIALS()

        # TODO: here we should check for 2fa, avoiding for demo

        if phone_email is None:
            # user is authenticated through email,
            # adding phone id as email for future login
            EmailAddress.objects.create_from_phone_id(phone_id, account)

        token, created = account.get_or_create_oauth_token(token_name)
        if created:
            response = rc.CREATED
        else:
            response = rc.ALL_OK
        response.content = {
            "consumer_key": token.consumer.key,
            "consumer_secret": token.consumer.secret,
            "token_key": token.token,
            "token_secret": token.token_secret,
            "token_name": token_name,
            "date_created": token.created_at,
            "date_updated": token.updated_at,
            "href": reverse('api-token', args=(token.token,)),
            "openid": account.openid_identifier,
        }
        return response


class EmailsHandler(BaseHandler):
    allowed_methods = ('GET',)

    def read(self, request):
        """Return email information."""


class RequestsHandler(BaseHandler):
    allowed_methods = ('POST',)

    @require_mime('json')
    def create(self, request):
        """Return whether a given oauth authorization header is valid.

        Receive an oauth Authorization header, an url and an http method and
        decide if the signature is valid (was created using valid credentials
        and belongs to an activa account).

        """
        data = request.data
        authorization = data.get('authorization', '')
        http_method = data.get('http_method', '')
        http_url = data.get('http_url', '')

        result = {'is_valid': False}
        headers = {'Authorization': authorization}
        try:
            oauth_request = oauth.OAuthRequest.from_request(
                http_method, http_url, headers=headers)
        except:
            logging.exception('RequestsHandler.create: could not build '
                              'OAuthRequest with the given parameters %r:',
                              data)
            oauth_request = None

        if oauth_request is None:
            return result

        oauth_datastore = SSODataStore(oauth_request)
        oauth_server = oauth.OAuthServer(oauth_datastore)
        oauth_server.add_signature_method(
            oauth.OAuthSignatureMethod_PLAINTEXT())
        oauth_server.add_signature_method(
            oauth.OAuthSignatureMethod_HMAC_SHA1())

        try:
            consumer, _, _ = oauth_server.verify_request(oauth_request)
        except:
            logging.exception('RequestsHandler.create: could not verify '
                              'request:')
            valid = False
        else:
            # signature is valid, need to also check the account exists
            # and is active
            valid = Account.objects.active_by_openid(consumer.key) is not None

        result['is_valid'] = valid
        return result
