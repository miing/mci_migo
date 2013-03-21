# Copyright 2010, 2012 Canonical Ltd.  This software is licensed under
# the GNU Affero General Public License version 3 (see the file
# LICENSE).

import logging

from django import forms
from django.conf import settings
from django.contrib import auth, messages
from django.contrib.auth.decorators import login_required
from django.core.urlresolvers import resolve, reverse
from django.db.models import F
from django.http import (
    Http404,
    HttpResponseNotAllowed,
    HttpResponseRedirect,
    urlencode,
)
from django.shortcuts import (
    get_object_or_404,
    render_to_response,
)
from django.template import RequestContext
from django.template.response import TemplateResponse
from django.utils.decorators import method_decorator
from django.utils.http import urlquote
from django.utils.translation import ugettext as _
from django.views.generic.base import View, TemplateResponseMixin
from gargoyle import gargoyle

from identityprovider import (
    emailutils,
    signed,
)
from identityprovider.forms import (
    ConfirmNewAccountForm,
    GenericEmailForm,
    LoginForm,
    NewAccountForm,
    OldNewAccountForm,
    ResetPasswordForm,
    TokenForm,
    TwoFactorForm,
    TwoFactorLoginForm,
)
from identityprovider.login import (
    authenticate_user,
    AuthenticationError,
)
from identityprovider.models import (
    Account,
    EmailAddress,
    get_type_of_token,
    verify_token_string,
)
from identityprovider.models.captcha import Captcha, VerifyCaptchaError
from identityprovider.models.const import (
    AccountStatus,
    EmailStatus,
    TokenType,
)
from identityprovider.models.openidmodels import OpenIDRPConfig
from identityprovider.models import twofactor
from identityprovider.models.twofactor import authenticate_device
from identityprovider.utils import (
    encrypt_launchpad_password,
    polite_form_errors,
)
from identityprovider.stats import stats
from identityprovider.views.utils import (
    get_rpconfig,
    get_rpconfig_from_request,
    is_safe_redirect_url,
)

from webui.decorators import (
    check_readonly,
    dont_cache,
    guest_required,
    limitlogin,
    requires_cookies,
    require_twofactor_enabled,
)
from webui.views.account import invalidate_email
from webui.views.utils import (
    add_captcha_settings,
    display_email_sent,
    set_session_email,
    redirection_url_for_token,
)
from webui.views import registration


ACCOUNT_CREATED = _("Your account was created successfully")
logger = logging.getLogger('sso')


def _add_non_field_error(form, exc):
    """Adds a generic error message to a form from an exception"""
    # apparently _errors is part of the public api
    # (https://docs.djangoproject.com/en/dev/ref/forms/validation/
    #   #described-later)
    errors = form._errors.setdefault(
        forms.forms.NON_FIELD_ERRORS,
        form.error_class())
    if hasattr(exc, 'messages'):  # django.forms.ValidationError
        errors.extend(exc.messages)
    else:  # plain old Exception
        errors.append(unicode(exc))


# Note: using TemplateResponseMixin rather than TemplateView, as it doesn't
# quite match our use case here
class LoginBaseView(TemplateResponseMixin, View):
    """Base class for login views. Handles context creation, rendering,
    initial set up, and error handling"""

    hide_sidebar = False

    def setup(self, request, token, rpconfig):
        if not rpconfig:
            rpconfig = get_rpconfig_from_request(request, token)
        return rpconfig

    def render(self, request, token, rpconfig, form):
        if token is None:
            login_path = reverse('login')
        else:
            login_path = reverse('login', args=[token])
        context = RequestContext(request, {
            'form': form,
            'hide_sidebar': self.hide_sidebar,
            'login_path': login_path,
            'next': request.GET.get('next'),
            'rpconfig': rpconfig,
            'token': token,
        })
        return self.render_to_response(context)

    def display_errors(self, request, token, rpconfig, form, error=None):
        """track and display nice errors, including extra ones"""
        # track login form errors
        stats.increment('flows.login', key='error', rpconfig=rpconfig)
        polite_form_errors(form._errors)
        if error:
            _add_non_field_error(form, error)
        return self.render(request, token, rpconfig, form)


class LoginView(LoginBaseView):
    template_name = 'registration/login.html'

    def get_login_type(self, request, token, rpconfig):
        required = twofactor.site_requires_twofactor_auth(request, token,
                                                          rpconfig)
        return required, TwoFactorLoginForm if required else LoginForm

    def get(self, request, token=None, rpconfig=None):
        rpconfig = self.setup(request, token, rpconfig)
        required2f, form_cls = self.get_login_type(request, token, rpconfig)
        # track login attempts
        stats.increment('flows.login', key='requested', rpconfig=rpconfig)
        return self.render(request, token, rpconfig, form_cls())

    def post(self, request, token=None, rpconfig=None):
        rpconfig = self.setup(request, token, rpconfig)
        result = self.get_login_type(request, token, rpconfig)
        site_twofactor, form_cls = result

        form = form_cls(request.POST)
        if not form.is_valid():
            return self.display_errors(request, token, rpconfig, form)

        # attempt user login
        email = form.cleaned_data['email']
        password = form.cleaned_data['password']
        try:
            account = authenticate_user(email, password, rpconfig)
            auth.login(request, account)
        except AuthenticationError as e:
            return self.display_errors(request, token, rpconfig, form, e)

        next_url = request.POST.get('next')

        # handle case where the user's account requires two factor but we
        # didn't know that until we authenticated them
        oath_token = form.cleaned_data.get('oath_token', None)
        if (not oath_token and
                twofactor.user_requires_twofactor_auth(request, account)):
            kwargs = {'token': token} if token else {}
            url = reverse('twofactor', kwargs=kwargs)
            if next_url and is_safe_redirect_url(next_url):
                # preserve next_url across get
                url += "?next=" + urlquote(next_url)
            return HttpResponseRedirect(url)

        if site_twofactor or oath_token:
            try:
                authenticate_device(account, oath_token)
                twofactor.login(request)
            except AuthenticationError as e:
                return self.display_errors(request, token, rpconfig, form, e)

        # track successful logins
        stats.increment('flows.login', key='success', rpconfig=rpconfig)

        # only clear limits if both succesfully auth
        limitlogin().reset_count(request)

        if next_url and is_safe_redirect_url(next_url):
            return HttpResponseRedirect(next_url)
        elif token:
            return HttpResponseRedirect('/%s/' % token)
        else:
            return HttpResponseRedirect('/')

    # To decorate class view methods with decorators designed for regular views
    # we must overwrite and decorate the dispatch method
    # OMFG. Srsly? :(
    # Docs: https://docs.djangoproject.com/en/dev/topics/class-based-views/
    @method_decorator(guest_required)
    @method_decorator(dont_cache)
    @method_decorator(limitlogin())
    @method_decorator(requires_cookies)
    def dispatch(self, *args, **kwargs):
        return super(LoginView, self).dispatch(*args, **kwargs)


class TwoFactorView(LoginBaseView):
    template_name = 'registration/twofactor.html'
    hide_sidebar = True

    def get(self, request, token=None, rpconfig=None):
        return self.render(request, token, rpconfig, TwoFactorForm())

    def post(self, request, token=None, rpconfig=None):
        account = request.user
        if account.twofactor_attempts is None:
            attempts = 1
            account.twofactor_attempts = 1
        else:
            attempts = account.twofactor_attempts + 1
            # we use an F-expression here to take the field value just before
            # saving, so we make the change as atomic as possible
            account.twofactor_attempts = F('twofactor_attempts') + 1

        form = TwoFactorForm(request.POST)
        if not form.is_valid():
            # save the updated twofactor_attempts value
            account.save()
            # refresh object from database before continuing
            # this is done so that the F-expression gets reset on the object
            # and we therefore avoid doing a duplicate increment
            request.user = Account.objects.get(id=account.id)
            return self.display_errors(request, token, rpconfig, form)

        try:
            authenticate_device(account, form.cleaned_data['oath_token'])
            twofactor.login(request)
            stats.increment('flows.login', key='success', rpconfig=rpconfig)
        except AuthenticationError as e:
            if attempts >= settings.TWOFACTOR_MAX_ATTEMPTS:
                logger.warning(
                    'Suspending account %r, %r due to too many twofactor '
                    'failures', account.openid_identifier, account.id)
                account.suspend()
                auth.logout(request)
                return suspended(request)
            # save the updated twofactor_attempts value
            account.save()
            # refresh object from database before continuing
            # this is done so that the F-expression gets reset on the object
            # and we therefore avoid doing a duplicate increment
            request.user = Account.objects.get(id=account.id)
            return self.display_errors(request, token, rpconfig, form, e)
        else:
            account.twofactor_attempts = 0
            account.save()

        limitlogin().reset_count(request)

        next_url = request.POST.get('next')
        if next_url and is_safe_redirect_url(next_url):
            return HttpResponseRedirect(next_url)
        elif token:
            return HttpResponseRedirect('/%s/' % token)
        return HttpResponseRedirect('/')

    @method_decorator(dont_cache)
    @method_decorator(limitlogin())
    # for this page, we need to be logged in but NOT twofactored
    @method_decorator(login_required)
    @method_decorator(require_twofactor_enabled)
    def dispatch(self, *args, **kwargs):
        if not 'rpconfig' in kwargs:
            request = args[0]
            token = kwargs.get('token')
            kwargs['rpconfig'] = get_rpconfig_from_request(request, token)
        return super(TwoFactorView, self).dispatch(*args, **kwargs)


class LogoutView(object):
    def get_language(self, user):
        try:
            return user.preferredlanguage
        except AttributeError:
            return None

    def set_language(self, response, language):
        if language:
            response.set_cookie(settings.LANGUAGE_COOKIE_NAME, language)

    def get_return_to_url(self, return_to, referer):
        rpconfig = OpenIDRPConfig.objects.for_url(return_to)
        if not return_to or rpconfig is None:
            return None
        elif referer is None or referer.startswith(rpconfig.trust_root):
            return return_to
        else:
            return None

    def set_orequest(self, session, token, raw_orequest):
        if token is not None and raw_orequest is not None:
            session[token] = raw_orequest

    def get_other_sites(self, user, trust_root):
        if not hasattr(user, 'sites_with_active_sessions'):
            return []
        return [site for site in user.sites_with_active_sessions()
                if trust_root != site.trust_root]

    def get_site_name(self, trust_root):
        rpconfig = OpenIDRPConfig.objects.for_url(trust_root)
        if not trust_root:
            return None
        elif rpconfig is None:
            return None
        elif rpconfig.displayname:
            return rpconfig.displayname
        else:
            return trust_root

    def compute_context(self, user, return_to, referrer):
        return_to = self.get_return_to_url(return_to, referrer)

        context = {
            'return_to_url': return_to,
            'return_to_site_name': self.get_site_name(return_to),
            'other_sites': self.get_other_sites(user, return_to),
        }
        return context

    def __call__(self, request, token=None):
        lang = self.get_language(request.user)

        context = self.compute_context(
            request.user,
            request.GET.get('return_to', None),
            request.META.get('HTTP_REFERER', None))
        context['rpconfig'] = get_rpconfig_from_request(request, token)

        # We don't want to lose session[token] when we log the user out
        raw_orequest = request.session.get(token, None)
        auth.logout(request)
        twofactor.logout(request)
        self.set_orequest(request.session, token, raw_orequest)

        template_file = ('%s/registration/logout.html' %
                         settings.BRAND_TEMPLATE_DIR)
        response = render_to_response(template_file,
                                      RequestContext(request, context))

        self.set_language(response, lang)
        return response


logout = LogoutView()


def enter_token(request, token=None):
    confirmation_code = request.REQUEST.get('confirmation_code')
    email = request.REQUEST.get('email') or request.session.get('token_email')
    params = {'confirmation_code': confirmation_code, 'email': email}
    if request.method == 'GET':
        form = TokenForm(initial=params)
    elif request.method == 'POST':
        form = TokenForm(params)
        if form.is_valid():
            confirmation = form.cleaned_data['confirmation']
            return _handle_confirmation(
                confirmation.token_type, confirmation_code, email, request,
                token=token)
    else:
        return HttpResponseNotAllowed(['GET', 'POST'])
    context = RequestContext(request, {
        'form': form,
        'token': token
    })
    return render_to_response('enter_token.html', context)


def _redirect_to_enter_token(confirmation_code=None, email=None):
    params = {}
    if confirmation_code is not None:
        params['confirmation_code'] = confirmation_code
    if email is not None:
        params['email'] = email
    return HttpResponseRedirect('/+enter_token?%s' % urlencode(params))


def claim_token(request, authtoken):
    email = request.GET.get('email') or request.session.get('token_email')
    if email is None:
        return _redirect_to_enter_token(confirmation_code=authtoken)
    token_type = get_type_of_token(authtoken)
    return _handle_confirmation(token_type, authtoken, email, request)


# As soon as _finish_account_creation doesn't need `request`, neither
# does this.
def _handle_confirmation(confirmation_type, confirmation_code, email, request,
                         token=None):
    """Handle a confirmation for an action requested on 'email'.

    Either finish the work in this view, or redirect to a view that can. Also
    accepts an optional OpenID-transaction token.

    """

    args = {
        'authtoken': confirmation_code,
        'email_address': email
    }
    if token is not None:
        args['token'] = token

    if confirmation_type == TokenType.PASSWORDRECOVERY:
        view = reset_password
    elif confirmation_type == TokenType.NEWPERSONLESSACCOUNT:
        # This is a slight inefficiency for now, as the caller may
        # already have retrieved the confirmation code from the
        # database.
        #
        # Also, all this code *really* wants to be a method on the
        # confirmation code... the objects are crying right now.
        confirmation = verify_token_string(confirmation_code, email)

        if (confirmation.displayname is not None and
                confirmation.password is not None):
            user, redirection_url = _finish_account_creation(
                confirmation, confirmation.displayname, confirmation.password,
                request)
            auth.login(request, user)
            messages.success(request, ACCOUNT_CREATED)
            return HttpResponseRedirect(redirection_url)

        view = old_confirm_account
        if 'token' in args:
            del args['token']

    elif confirmation_type == TokenType.VALIDATEEMAIL:
        view = confirm_email
    elif confirmation_type == TokenType.INVALIDATEEMAIL:
        view = invalidate_email
    else:
        msg = ('Unknown type %s for confirmation code "%s"' %
               (confirmation_type, confirmation_code))
        logger.error(msg)
        raise Http404(msg)

    url = reverse(view, kwargs=args)
    return HttpResponseRedirect(url)


# This accepts displayname and password as separate parameters for
# now.  After removing the old confirmation method, this function can
# pull those params directly from atrequest.
#
# This function is currently called from two places, and at each place
# is followed by the exact same code to log the user in and setup some
# session stuff.  I've decided to not include that code in this
# function, to keep this function isolated from the view layer and
# easy to test.  ALTHOUGH, it does currently have other view
# dependencies (for determining the creation rationale), which
# *should* also be moved out.  Maybe rationale should be determined
# when the token is created, and stored?
def _finish_account_creation(atrequest, displayname, password, request):
    """Creates the account according to the given token.  Returns the
    new user, already authorized, and the URL to redirect to."""
    #displayname = atrequest.displayname
    email_address = atrequest.email
    #password = atrequest.encrypted_password
    creation_rationale = None
    if atrequest.redirection_url is None:
        atrequest.redirection_url = '/'
    if atrequest.redirection_url.endswith('+decide'):
        # Try to determine creation rationale from RP config
        view, args, kwargs = resolve(atrequest.redirection_url)
        if 'token' in kwargs:
            try:
                raw_orequest = request.session.get(
                    kwargs['token'], None)
                openid_request = signed.loads(
                    raw_orequest, settings.SECRET_KEY)
                rpconfig = get_rpconfig(openid_request.trust_root)
                if rpconfig is not None:
                    creation_rationale = rpconfig.creation_rationale
            except Exception:
                pass
    # test if account has already been created
    account = Account.objects.get_by_email(email_address)
    if account is not None:
        # account already created, just needs confirmation
        email = EmailAddress.objects.get(email=email_address, account=account)
        email.status = EmailStatus.PREFERRED
        email.save()
    else:
        # account has not yet been created. Let's create it
        account = Account.objects.create_account(
            displayname, email_address, password, creation_rationale,
            password_encrypted=True)
    atrequest.consume()
    user = auth.authenticate(username=email_address,
                             encrypted_password=password)
    return user, atrequest.redirection_url


@check_readonly
def new_account(request, token=None):
    if gargoyle.is_active('ALLOW_UNVERIFIED'):
        return registration.new_account(request, token)
    else:
        return old_new_account(request, token)


@guest_required
@check_readonly
@requires_cookies
def old_new_account(request, token=None):
    # Need this to display RP info when coming from a consumer
    rpconfig = get_rpconfig_from_request(request, token)

    # {{workflow}}
    old = 'old' in request.REQUEST
    form_class = OldNewAccountForm if old else NewAccountForm

    if request.method == 'GET':
        # track number of registration requests by consumer
        stats.increment('flows.new_account', key='requested',
                        rpconfig=rpconfig)

        if 'email' in request.GET:
            form = form_class(initial={'email': request.GET['email']})
        else:
            form = form_class()
    elif request.method == 'POST':
        form = form_class(request.POST)
        if form.is_valid():

            response = _verify_captcha_response(
                'registration/new_account.html', request, form)
            if response:
                # track number of captcha verification failures
                stats.increment('flows.new_account', key='error.captcha',
                                rpconfig=rpconfig)
                return response

            # {{workflow}} All these fields will always be available
            # by this point.
            displayname = form.cleaned_data.get('displayname')
            email = form.cleaned_data['email']
            password = form.cleaned_data.get('password', None)
            if password is not None:
                # password validation enforced by the form
                # at this point, password complies with policy since
                # form.is_valid() is True
                encrypted_password = encrypt_launchpad_password(password)
            else:
                encrypted_password = password

            account = Account.objects.get_by_email(email)
            if account is None:
                redirection_url = redirection_url_for_token(token)
                # XXX: old is now IGNORED, will be removed when
                # {{workflow}} is removed
                emailutils.send_new_user_email(
                    account=None, email=email, platform='web',
                    redirection_url=redirection_url,
                    displayname=displayname, password=encrypted_password)
                set_session_email(request.session, email)
                # No need to handle invalid email error since form.is_valid()
                # ensures that the given email is valid
            else:
                # Only send email if the account is active; otherwise, a
                # disabled account can be spammed.
                if not account.is_active:
                    logger.debug("In view 'new_account' email was not sent "
                                 "out because account '%s' is not active",
                                 account.displayname)
                elif account.preferredemail is None:
                    logger.debug("In view 'new_account' email was not sent "
                                 "out because account '%s' has no preferred "
                                 "email.", account.displayname)
                else:
                    emailutils.send_impersonation_email(
                        account.preferredemail.email)

            msgs = dict(email_to=email,
                        email_from=settings.NOREPLY_FROM_ADDRESS)
            return display_email_sent(
                request,
                email,
                _("Account creation mail sent"),
                _("We&rsquo;ve just emailed "
                  "%(email_to)s (from %(email_from)s) to confirm "
                  "your address.") % msgs,
                token=token,
                rpconfig=rpconfig
            )
        else:
            polite_form_errors(form._errors)
            # track number of form errors
            stats.increment('flows.new_account', key='error.form',
                            rpconfig=rpconfig)

    context = RequestContext(request, add_captcha_settings({
        'form': form,
        # {{workflow}}
        'old': old,
        'rpconfig': rpconfig,
        'captcha_required': True,
        'token': token,
    }))
    return render_to_response('registration/new_account.html', context)


def _verify_captcha_response(template, request, form):
    captcha = Captcha(request.POST.get('recaptcha_challenge_field'))
    captcha_solution = request.POST.get('recaptcha_response_field')
    email = request.POST.get('email', '')
    ip_addr = request.environ["REMOTE_ADDR"]
    try:
        verified = captcha.verify(captcha_solution, ip_addr, email)
        if verified:
            return None
    except VerifyCaptchaError:
        logging.exception("reCaptcha connection error")

    # not verified
    return render_to_response(
        template,
        RequestContext(request, add_captcha_settings({
            'form': form,
            'captcha_error': ('&error=%s' % captcha.message),
            'captcha_required': True})))


# {{workflow}}
@check_readonly
def old_confirm_account(request, authtoken, email_address, token=None):
    if request.user.is_authenticated():
        return HttpResponseRedirect('/+logout-to-confirm')

    atrequest = verify_token_string(authtoken, email_address)
    if (atrequest is None or
            atrequest.token_type != TokenType.NEWPERSONLESSACCOUNT):
        return HttpResponseRedirect('/+bad-token')

    if request.method == 'GET':
        form = ConfirmNewAccountForm()
    elif request.method == 'POST':
        form = ConfirmNewAccountForm(request.POST)
        if form.is_valid():
            displayname = form.cleaned_data['displayname']
            password = encrypt_launchpad_password(
                form.cleaned_data['password'])
            user, redirection_url = _finish_account_creation(
                atrequest, displayname, password, request)
            auth.login(request, user)
            messages.success(request, ACCOUNT_CREATED)
            return HttpResponseRedirect(redirection_url)
    context = RequestContext(request, {'form': form, 'token': token})
    return render_to_response('registration/old_confirm_new_account.html',
                              context)


@check_readonly
def confirm_account(request, authtoken, email_address, token=None):
    if request.user.is_authenticated():
        return HttpResponseRedirect('/+logout-to-confirm')

    # Need this for displaying metrics per RP
    rpconfig = get_rpconfig_from_request(request, token)

    atrequest = verify_token_string(authtoken, email_address)
    if (atrequest is None or
            atrequest.token_type != TokenType.NEWPERSONLESSACCOUNT):
        # track wrong tokens being used
        stats.increment('flows.new_account', key='error.token',
                        rpconfig=rpconfig)
        return HttpResponseRedirect('/+bad-token')

    if request.method == 'GET':
        context = RequestContext(request, {'email': email_address,
                                           'token': token})
        return render_to_response('registration/confirm_new_account.html',
                                  context)

    if request.method != 'POST':
        return HttpResponseNotAllowed(['GET', 'POST'])

    user, redirection_url = _finish_account_creation(
        atrequest, atrequest.displayname, atrequest.password, request)
    auth.login(request, user)
    messages.success(request, ACCOUNT_CREATED)

    # track number of completed registrations by consumer
    stats.increment('flows.new_account', key='success', rpconfig=rpconfig)

    return HttpResponseRedirect(redirection_url)


def confirm_email(request, authtoken, email_address, token=None):
    if not twofactor.is_authenticated(request):
        messages.warning(request,
                         _('Please log in to use this confirmation code'))
        next_url = urlquote(request.get_full_path())
        return HttpResponseRedirect('%s?next=%s' % (settings.LOGIN_URL,
                                                    next_url))
    atrequest = verify_token_string(authtoken, email_address)
    if (atrequest is None or
            atrequest.token_type != TokenType.VALIDATEEMAIL):
        return HttpResponseRedirect('/+bad-token')

    email = get_object_or_404(EmailAddress, email__iexact=atrequest.email)
    if request.user.id != email.account.id:
        # The user is authenticated to a different account.
        # Potentially, the token was leaked or intercepted.  Let's
        # delete it just in case.  The real user can generate another
        # token easily enough.
        atrequest.delete()
        raise Http404

    if request.method == 'POST':
        # only confirm the email address if the form was submitted
        email.status = EmailStatus.VALIDATED
        email.save()
        atrequest.consume()
        msg = _("The email address {email} has been validated")
        messages.success(request, msg.format(email=email))
        return HttpResponseRedirect(
            atrequest.redirection_url or reverse('account-index')
        )

    # form was not submitted
    context = RequestContext(request, {'email': email.email, 'token': token})
    return render_to_response('account/confirm_new_email.html', context)


def bad_token(request):
    return TemplateResponse(request, 'bad_token.html')


def logout_to_confirm(request):
    return TemplateResponse(request, 'registration/logout_to_confirm.html')


def deactivated(request):
    return TemplateResponse(request, 'account/deactivated.html')


def suspended(request):
    return TemplateResponse(request, 'account/suspended.html')


def _handle_reset_request(request, email, token):
    account = Account.objects.get_by_email(email)
    if account is not None:
        verified_emails = account.verified_emails()
        if account.can_reset_password:
            redirection_url = redirection_url_for_token(token)
            if not verified_emails.filter(email=email).count() > 0:
                # provided email is not verified
                # send email to verified addresses instead
                # XXXX should not send multiple emails here!
                for email_obj in verified_emails:
                    emailutils.send_password_reset_email(account,
                                                         email_obj.email,
                                                         redirection_url)
            else:
                emailutils.send_password_reset_email(account, email,
                                                     redirection_url)
            set_session_email(request.session, email)
        elif verified_emails.count() == 0:
            # user does not have any verified email address
            # he should contact support
            condition = ("account '%s' has no verified email address" %
                         account.displayname)
            logger.debug("In view 'forgot_password' email was not "
                         "sent out because %s" % condition)
        else:
            # log why email was not sent
            condition = ("account '%s' is not active" %
                         account.displayname)
            logger.debug("In view 'forgot_password' email was not "
                         "sent out because %s" % condition)
    else:
        # they've tried to reset with an invalid email, so send them an email
        # on how to create an account
        emailutils.send_invitation_after_password_reset(email)


@guest_required
@check_readonly
@requires_cookies
def forgot_password(request, token=None):
    # Need this for displaying metrics per RP
    rpconfig = get_rpconfig_from_request(request, token)
    if request.method == 'GET':
        # track forgot password requests
        stats.increment('flows.forgot_password', key='requested',
                        rpconfig=rpconfig)

        if 'email' in request.GET:
            form = GenericEmailForm(initial={'email': request.GET['email']})
        else:
            form = GenericEmailForm()
    elif request.method == 'POST':
        form = GenericEmailForm(request.POST)
        if form.is_valid():
            response = _verify_captcha_response(
                'registration/forgot_password.html', request, form)
            if response:
                # track captcha errors
                stats.increment('flows.forgot_password', key='error.captcha',
                                rpconfig=rpconfig)
                return response

            email = form.cleaned_data['email']

            # handle the reset request
            _handle_reset_request(request, email, token)

            # regardless of result, we always display the same information back
            # to the user
            msgs = {
                'email_to': email,
                'email_from': settings.NOREPLY_FROM_ADDRESS,
                'support_form_url': settings.SUPPORT_FORM_URL,
            }
            reason = _(
                "We've just emailed "
                "%(email_to)s (from %(email_from)s) with "
                "instructions on resetting your password.<br/><br/>"
                "If the email address you provided has not been verified "
                "we'll use your account's verified email address instead. "
                "If you don't have a verified email address please "
                "<a href='%(support_form_url)s'>contact support</a>."
            ) % msgs
            return display_email_sent(
                request,
                email,
                _("Forgotten your password?"),
                reason,
                _("Check that you&rsquo;ve actually "
                  "entered a subscribed email address."),
                token=token,
                rpconfig=rpconfig,
            )
        else:
            # track form errors
            stats.increment('flows.forgot_password', key='error.form',
                            rpconfig=rpconfig)
            polite_form_errors(form._errors)

    captcha_settings = dict(form=form, rpconfig=rpconfig, token=token)
    context = RequestContext(request, add_captcha_settings(captcha_settings))
    return render_to_response('registration/forgot_password.html', context)


@guest_required
def reset_password(request, authtoken, email_address, token=None):
    # Need this for displaying metrics per RP
    rpconfig = get_rpconfig_from_request(request, token)

    atrequest = verify_token_string(authtoken, email_address)
    account = atrequest and atrequest.requester

    if (atrequest is None or
            atrequest.token_type != TokenType.PASSWORDRECOVERY or
            not account.can_reset_password):
        # track bad token error
        stats.increment('flows.forgot_password', key='error.token',
                        rpconfig=rpconfig)
        # we hide the fact the the account is inactive, to avoid
        # exposing valid accounts. however, deactivated accounts can be
        # reactivated.
        return HttpResponseRedirect('/+bad-token')

    if request.method == 'POST':
        form = ResetPasswordForm(request.POST)
        if form.is_valid():
            password = form.cleaned_data['password']
            if not account.is_active and account.can_reactivate:
                # if account can be reactivated, set the preferred email
                # address
                email_obj, created = EmailAddress.objects.get_or_create(
                    account=account,
                    email=atrequest.requester_email,
                    defaults={'status': EmailStatus.PREFERRED})
                if not created:
                    account.preferredemail = email_obj
                # reactivate the account
                account.status = AccountStatus.ACTIVE
                account.save()
                msg = _("Your account was reactivated, and the preferred "
                        "email address was set to {email}.")
                messages.info(request, msg.format(email=email_obj.email))
            email = account.preferredemail.email
            account.set_password(password)
            user = auth.authenticate(username=email, password=password)
            auth.login(request, user)
            atrequest.consume()
            # track password recovery success
            stats.increment('flows.forgot_password', key='success',
                            rpconfig=rpconfig)
            return HttpResponseRedirect(atrequest.redirection_url)

        # track form errors
        stats.increment('flows.forgot_password', key='error.form',
                        rpconfig=rpconfig)
    else:
        form = ResetPasswordForm()
    context = RequestContext(request, {'form': form, 'token': token})
    return render_to_response('registration/reset_password.html', context)


def static_page(request, page_name):
    if settings.BRAND not in ('ubuntu', 'ubuntuone'):
        raise Http404

    return render_to_response('static/%s.html' % page_name,
                              RequestContext(request))
