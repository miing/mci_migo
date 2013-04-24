# Copyright 2010, 2012 Canonical Ltd.  This software is licensed under
# the GNU Affero General Public License version 3 (see the file
# LICENSE).

import logging

from urlparse import urljoin

from django.conf import settings
from django.contrib.auth.models import User
from django.contrib import auth, messages
from django.core.urlresolvers import reverse
from django.http import Http404, HttpResponseRedirect
from django.shortcuts import render_to_response, get_object_or_404
from django.template import RequestContext
from django.template.response import TemplateResponse
from django.views.decorators.vary import vary_on_headers
from oauth_backend.models import (
    Consumer,
    Token,
)

from openid.yadis.constants import YADIS_HEADER_NAME, YADIS_CONTENT_TYPE

from identityprovider.cookies import set_test_cookie, test_cookie_worked
from identityprovider.emailutils import (
    send_invalidation_email_notice,
    send_validation_email_request,
)
from identityprovider.forms import EditAccountForm, NewEmailForm
from identityprovider.models import (
    AuthToken,
    EmailAddress,
)
from identityprovider.models.const import (
    AccountStatus,
    EmailStatus,
    TokenType,
)
from identityprovider.models.twofactor import is_twofactor_enabled
from identityprovider.signals import account_email_added
from identityprovider.utils import get_object_or_none
from identityprovider.views.server import xrds
from identityprovider.views.utils import (
    get_rpconfig_from_request,
    require_testing_enabled,
)

from webui.decorators import (
    check_readonly,
    sso_login_required,
)
from webui.views.const import (
    DETAILS_UPDATED,
    EMAIL_DELETED,
    TOKEN_DELETED,
    VALIDATE_EMAIL,
    VALIDATE_EMAIL_DESC,
)
from webui.views.ui import LoginView
from webui.views.utils import (
    display_email_sent,
    redirection_url_for_token,
    set_session_email
)

logger = logging.getLogger(__name__)


@vary_on_headers('Accept')
def index(request, token=None):
    accept = request.META.get('HTTP_ACCEPT', '')
    if YADIS_CONTENT_TYPE in accept:
        return xrds(request)

    if request.user.is_authenticated():
        resp = account_edit(request, token)
    else:
        # We simply render LoginView's get() method as any posted
        # login data will be handled by the configured 'login' url.
        # (ie. /+login currently).
        resp = LoginView(request=request).get(request, token=token)
        # Perhaps the browser sent us the test cookie, or perhaps it
        # didn't.  We'll tell Django that we want one, and it will be
        # intelligent and not send it out again if the browser *did*
        # send it to us.
        set_test_cookie(resp)
    resp[YADIS_HEADER_NAME] = '%s+xrds' % settings.SSO_ROOT_URL
    return resp


def cookie(request):
    next = request.REQUEST.get('next', '/')
    if test_cookie_worked(request):
        return HttpResponseRedirect(next)
    # Send the cookie again, so that the user can hit reload on the
    # page we return to continue on.
    return set_test_cookie(render_to_response('cookies.html'))


@sso_login_required
def account_edit(request, token=None):
    rpconfig = get_rpconfig_from_request(request, token)
    account = request.user

    msg = 'Called account_edit with request.user being None. Impossible!'
    assert account is not None, msg

    enable_device_prefs = (is_twofactor_enabled(request) and
                           account.devices.count() > 0)
    if request.method == 'POST' and not settings.READ_ONLY_MODE:
        form = EditAccountForm(request.POST, instance=account,
                               enable_device_prefs=enable_device_prefs)
        if form.is_valid():
            form.save()
            messages.success(request, DETAILS_UPDATED)
            return HttpResponseRedirect(request.path)
    else:
        form = EditAccountForm(instance=account,
                               enable_device_prefs=enable_device_prefs)

    need_backup_device_warning = (enable_device_prefs and
                                  account.need_backup_device_warning)

    # if user has just registered, do not show warning about unverified email
    new_account = (request.META.get('HTTP_REFERER') ==
                   urljoin(settings.SSO_ROOT_URL, reverse('new_account')))
    preferred_email = account.preferredemail  # cache it, one access to the DB
    verified = preferred_email and preferred_email.is_verified
    need_verify_email_warning = not verified and not new_account

    if enable_device_prefs:
        paper_renewals = list(request.user.paper_devices_needing_renewal)
    else:
        paper_renewals = []

    context = RequestContext(request, {
        'current_section': 'account',
        'account': account,
        'account_displayname': account.displayname,
        'last_authenticated_sites': account.last_authenticated_sites(limit=10),
        'unverified_emails': account.unverified_emails(),
        'enable_device_prefs': enable_device_prefs,
        'need_backup_device_warning': need_backup_device_warning,
        'paper_devices_needing_renewal': paper_renewals,
        'need_verify_email_warning': need_verify_email_warning,
        'unverified_email': preferred_email,
        'form': form,
        'token': token,
        'rpconfig': rpconfig,
    })
    return render_to_response('account/edit.html', context)


@sso_login_required
def account_emails(request):
    account = request.user
    form = NewEmailForm()
    context = RequestContext(request, {
        'current_section': 'emails',
        'account': account,
        'account_displayname': account.displayname,
        'verified_emails': account.verified_emails(),
        'unverified_emails': account.unverified_emails(),
        'form': form,
    })
    return render_to_response('account/emails.html', context)


@require_testing_enabled
@sso_login_required
def account_deactivate(request, token=None):
    account = request.user
    for email in account.emailaddress_set.all():
        email.status = EmailStatus.NEW
        email.save()
    account.status = AccountStatus.DEACTIVATED
    account.save()

    # We don't want to lose session[token] when we log the user out
    raw_orequest = request.session.get(token, None)
    auth.logout(request)
    if token is not None and raw_orequest is not None:
        request.session[token] = raw_orequest
    return HttpResponseRedirect(reverse('deactivated'))


def _send_verification_email(request, email, tokenid=None):
    # TODO: This makes use of `tokenid` if it's passed in, but the
    # call to `send_validation_email_request` always generates a new
    # token.  Is this right?

    # If there are any unverified emails that match they should be deleted.
    EmailAddress.objects.filter(email__iexact=email,
                                status=EmailStatus.NEW).delete()

    # Ensure that this account has such email address; return value is not used
    request.user.emailaddress_set.get_or_create(
        email=email, status=EmailStatus.NEW)

    redirection_url = redirection_url_for_token(tokenid)

    send_validation_email_request(request.user, email, redirection_url)
    set_session_email(request.session, email)

    return display_email_sent(
        request,
        email,
        VALIDATE_EMAIL,
        VALIDATE_EMAIL_DESC.format(email_to=email,
                                   email_from=settings.NOREPLY_FROM_ADDRESS)
    )


@sso_login_required
@check_readonly
def new_email(request, token=None, emailid=None):
    form = NewEmailForm()

    if request.method == 'POST' and not settings.READ_ONLY_MODE:
        form = NewEmailForm(request.POST, account=request.user)
        if form.is_valid():
            email = form.cleaned_data['newemail']
            account_email_added.send(
                openid_identifier=request.user.openid_identifier,
                sender=None)
            return _send_verification_email(request, email, token)

    context = RequestContext(request, {'form': form})
    return render_to_response('account/new_email.html', context)


@sso_login_required
def verify_email(request, token=None):
    emailid = request.GET.get('id', 0)
    email = get_object_or_404(request.user.emailaddress_set, pk=emailid,
                              status=EmailStatus.NEW)
    return _send_verification_email(request, email.email, token)


def invalidate_email(request, authtoken, email_address):
    authtoken = get_object_or_404(
        AuthToken, token=authtoken, email=email_address,
        token_type=TokenType.INVALIDATEEMAIL)
    if not authtoken.active:
        return HttpResponseRedirect(reverse('bad_token'))

    if request.method == 'GET':
        return TemplateResponse(
            request, 'account/confirm_email_invalidation.html',
            context=dict(email=email_address))

    authtoken.consume()

    # consume any other active token for the same email address
    for t in AuthToken.objects.filter(email=email_address, date_consumed=None):
        t.consume()

    auth.logout(request)
    response = TemplateResponse(request, 'account/invalidate_email.html',
                                context=dict(email=email_address))

    # email may not exist since the user may have tried an operation with
    # an email unknown to our system
    emails = EmailAddress.objects.filter(email=email_address)
    if emails.count() == 0:
        # This case matches, for example, registration web where the Account
        # is not created until the user validates the email address.
        # To be changed pretty soon (nessita, 2013-01-11).
        logger.info('Received a request to invalidate email %r, but a matching'
                    ' EmailAddress does not exist in the system.',
                    email_address)
        return response

    if emails.count() > 1:
        logger.warning('While trying to invalidate email %r, found more than '
                       '1 EmailAddress matching the email.', email_address)

    logger.info('Setting email %r status to invalidated.', email_address)
    email = emails[0]
    account = email.account
    email.invalidate()

    if account is None:
        logger.warning("Received a request to invalidate email %r, but the "
                       "email's account is None.", email_address)
        return response

    # notify the account of the email invalidation, prioritize validated emails
    if account.preferredemail is not None:
        send_invalidation_email_notice(account, invalidated_email=email.email)

    user = get_object_or_none(User, username=account.openid_identifier)
    if user is not None:
        oauth_consumer = get_object_or_none(Consumer, user=user)
        if oauth_consumer is not None:
            # invalidate all login tokens by deleting them
            logger.info('Invalidating oauth tokens for %r', email_address)
            oauth_consumer.token_set.all().delete()

    return response


@sso_login_required
def delete_email(request, token=None):
    emailid = request.GET.get('id', 0)
    email = get_object_or_404(
        request.user.emailaddress_set,
        pk=emailid,
        status__in=[EmailStatus.NEW, EmailStatus.VALIDATED])
    if request.method == 'POST':
        redirection_url = (token and redirection_url_for_token(token) or
                           '/+emails')
        email.delete()
        messages.success(request, EMAIL_DELETED.format(email=email.email))
        return HttpResponseRedirect(redirection_url)
    else:
        context = RequestContext(request, {
            'email': email.email,
        })
        return render_to_response('account/delete_email.html', context)


@sso_login_required
@check_readonly
def applications(request):
    if settings.BRAND not in ('ubuntu', 'ubuntuone'):
        raise Http404

    if request.method == 'POST':
        token_id = request.POST.get('token_id')
        if token_id:
            try:
                token = request.user.oauth_tokens().get(pk=token_id)
                token.delete()
                messages.success(request,
                                 TOKEN_DELETED.format(name=token.name))
            except (AttributeError, Token.DoesNotExist):
                pass
        return HttpResponseRedirect('/+applications')
    else:
        tokens = request.user.oauth_tokens()
        context = RequestContext(request, {
            'current_section': 'applications',
            'tokens': tokens,
        })
        return render_to_response('account/applications.html', context)
