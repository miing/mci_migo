# Copyright 2010, 2012 Canonical Ltd.  This software is licensed under
# the GNU Affero General Public License version 3 (see the file
# LICENSE).

from django.conf import settings
from django.contrib import auth, messages
from django.template import RequestContext
from django.template.response import TemplateResponse
from django.http import (
    HttpResponseNotAllowed,
    HttpResponseRedirect,
)
from django.utils.translation import ugettext as _

from gargoyle import gargoyle
from ssoclient.v2 import errors as api_errors

from identityprovider.apiutils import get_api_client
from identityprovider.forms import (
    GenericEmailForm,
    NewAccountForm,
)
from identityprovider.stats import stats
from identityprovider.utils import (
    get_current_brand,
    polite_form_errors,
    redirection_url_for_token,
)
from identityprovider.views.utils import get_rpconfig_from_request

from webui.decorators import (
    check_readonly,
    redirect_home_if_logged_in,
    requires_cookies,
)
from webui.views.utils import (
    add_captcha_settings,
    display_email_sent,
    set_session_email,
)


ACCOUNT_CREATED = _('Your account was created successfully.')
CORRECT_ERRORS = _('Please correct the errors below.')
VERIFY_EMAIL_SENT = _('We have emailed %(email_to)s (from %(email_from)s), '
                      'please check your inbox to verify your email address.')


@redirect_home_if_logged_in
@check_readonly
@requires_cookies
def new_account(request, token=None):
    captcha_required = (
        not gargoyle.is_active('OPTIONAL_CAPTCHA', request) or
        gargoyle.is_active('CAPTCHA', request)
    )
    captcha_error = ''
    rpconfig = get_rpconfig_from_request(request, token)

    def collect_stats(key):
        stats.increment('flows.new_account', key=key, rpconfig=rpconfig)

    if request.method == 'GET':
        collect_stats('requested')
        form = NewAccountForm(initial={'email': request.GET.get('email')})

    elif request.method == 'POST':
        form = NewAccountForm(request.POST)
        if form.is_valid():
            data = dict((k, v) for k, v in form.cleaned_data.items()
                        if k in ('email', 'password', 'displayname'))
            data['captcha_id'] = request.POST.get(
                'recaptcha_challenge_field'
            )
            data['captcha_solution'] = request.POST.get(
                'recaptcha_response_field'
            )
            # we'll handle our own capture generation
            data['create_captcha'] = False

            url = redirection_url_for_token(token)

            try:
                api = get_api_client(request)
                api.register(data)

            except api_errors.InvalidData as e:
                # we shouldn't really get this, as the form will have validated
                # the data, but just in case...
                form._errors.update(e.extra)
                collect_stats('error.form')

            except api_errors.AlreadyRegistered:
                collect_stats('error.email')
                form._errors['email'] = ['Invalid Email']

            except api_errors.CaptchaRequired as e:
                captcha_required = True
                collect_stats('captcha_required')

            except api_errors.CaptchaFailure as e:
                captcha_required = True
                captcha_error = '&error=' + e.extra.get('captcha_message', '')
                collect_stats('error.captcha')

            else:
                collect_stats('success')

                # TODO: remove, but still needed atm
                set_session_email(request.session, data['email'])

                user = auth.authenticate(
                    username=data['email'],
                    password=data['password']
                )
                auth.login(request, user)

                msg_data = dict(email_to=data['email'],
                                email_from=settings.NOREPLY_FROM_ADDRESS)
                msgs = (ACCOUNT_CREATED, VERIFY_EMAIL_SENT % msg_data)
                messages.success(request, ' '.join(msgs), 'temporary')
                return HttpResponseRedirect(url)

        else:

            if get_current_brand() == 'ubuntuone':
                messages.error(request, CORRECT_ERRORS)

            collect_stats('error.form')

    if form._errors:
        polite_form_errors(form._errors)

    context = {
        'form': form,
        'rpconfig': rpconfig,
        'token': token,
        'captcha_required': captcha_required,
        'captcha_error': captcha_error,
    }
    if captcha_required:
        context = add_captcha_settings(context)

    template = 'registration/new_account.html'
    return TemplateResponse(request, template, context)


@check_readonly
@requires_cookies
def forgot_password(request, token=None):
    # Need this for displaying metrics per RP
    rpconfig = get_rpconfig_from_request(request, token)

    def collect_stats(key):
        stats.increment('flows.forgot_password', key=key, rpconfig=rpconfig)

    if request.method == 'GET':
        # track forgot password requests
        collect_stats('requested')
        form = GenericEmailForm(initial={'email': request.GET.get('email')})

    elif request.method == 'POST':
        form = GenericEmailForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']

            try:
                api = get_api_client(request)
                api.request_password_reset(email, token=token)
                set_session_email(request.session, email)

            except api_errors.InvalidData as e:
                # we shouldn't really get this, as the form will have validated
                # the data, but just in case...
                form._errors.update(e.extra)
                collect_stats('error.form')

            except api_errors.EmailInvalidated as e:
                collect_stats('error.email_invalidated')

            except api_errors.AccountSuspended as e:
                collect_stats('error.account_suspended')

            except api_errors.AccountDeactivated as e:
                collect_stats('error.account_deactivated')

            except api_errors.CanNotResetPassword as e:
                collect_stats('error.can_not_reset_password')

            except api_errors.TooManyTokens as e:
                collect_stats('error.too_many_tokens')

            except (api_errors.CaptchaRequired,
                    api_errors.CaptchaFailure) as e:
                collect_stats('error.captcha')

            # regardless of result, we always display the same information back
            # to the user
            msgs = {
                'email_to': email,
                'email_from': settings.NOREPLY_FROM_ADDRESS,
                'support_form_url': settings.SUPPORT_FORM_URL,
            }

            if get_current_brand() == 'ubuntuone':
                heading = 'Reset password'
                reason = _(
                    "We have sent an email to %(email_to)s. To continue, "
                    "click on the link in your email, or enter the "
                    "confirmation code below."
                ) % msgs
            else:
                heading = 'Forgotten your password?'
                reason = _(
                    "We've just emailed "
                    "%(email_to)s (from %(email_from)s) with "
                    "instructions on resetting your password.<br/><br/>"
                    "If the email address you provided has not been "
                    "verified we'll use your account's verified email "
                    "address instead. If you don't have a verified email "
                    "address please "
                    "<a href='%(support_form_url)s'>contact support</a>."
                ) % msgs
            return display_email_sent(
                request,
                email,
                heading,
                reason,
                _("Check that you&rsquo;ve actually "
                  "entered a subscribed email address."),
                token=token,
                rpconfig=rpconfig,
            )

        else:
            # track form errors
            collect_stats('error.form')
            polite_form_errors(form._errors)

    else:
        return HttpResponseNotAllowed(['GET', 'POST'])

    captcha_settings = dict(form=form, rpconfig=rpconfig, token=token)
    context = RequestContext(request, add_captcha_settings(captcha_settings))
    template = 'registration/forgot_password.html'
    return TemplateResponse(request, template, context)
