# Copyright 2010, 2012 Canonical Ltd.  This software is licensed under
# the GNU Affero General Public License version 3 (see the file
# LICENSE).

from django.conf import settings
from django.contrib import auth, messages
from django.template.response import TemplateResponse
from django.http import HttpResponseRedirect
from django.utils.translation import ugettext as _

from gargoyle import gargoyle

from identityprovider.forms import NewAccountForm

from identityprovider.utils import polite_form_errors
from identityprovider.apiutils import get_api_client

from identityprovider.stats import stats
from identityprovider.views.utils import get_rpconfig_from_request

from webui.decorators import (
    check_readonly,
    guest_required,
    requires_cookies,
)

from webui.views.utils import (
    add_captcha_settings,
    redirection_url_for_token,
    set_session_email,
)

from ssoclient.v2 import errors as api_errors

ACCOUNT_CREATED = _('Your account was created successfully.')
VERIFY_EMAIL_SENT = _('We have emailed %(email_to)s (from %(email_from)s), '
                      'please check your inbox to verify your email address.')


@guest_required
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
                messages.success(request, ' '.join(msgs))
                return HttpResponseRedirect(url)

        else:
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
