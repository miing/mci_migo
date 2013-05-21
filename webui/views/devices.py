# Copyright 2012 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

import re
from base64 import b16encode
from collections import namedtuple

from django.contrib import messages
from django.contrib.auth.views import redirect_to_login
from django.core.urlresolvers import reverse
from django.conf import settings
from django.http import Http404, HttpResponseRedirect
from django.shortcuts import get_object_or_404, render_to_response
from django.template import RequestContext
from django.template.response import TemplateResponse
from django.views.generic import View
from django.utils.translation import ugettext as _
from gargoyle.decorators import switch_is_active
from gargoyle import gargoyle
from M2Crypto.Rand import rand_bytes
from oath.hotp import accept_hotp, hotp

from identityprovider.forms import HOTPDeviceForm, DeviceRenameForm
from identityprovider.models import AuthenticationDevice
from identityprovider.models import twofactor
from identityprovider.models.twofactor import get_otp_type

from webui.decorators import require_twofactor_enabled, sso_login_required
from webui.views.const import (
    DEVICE_ADDED,
    DEVICE_DELETED,
    DEVICE_GENERATION_WARNING,
    DEVICE_RENAMED,
    OTP_MATCH_ERROR,
)
from webui.views.utils import HttpResponseSeeOther, allow_only


DEVICE_ADDITION = 'device-addition'
DEVICE_LIST = 'device-list'
CodePageDetails = namedtuple('CodePageDetails', 'codes page start position')


def get_context(request, **kwargs):
    kwargs['current_section'] = 'devices'
    return RequestContext(request, kwargs)


device_types = {
    'yubi': _('Yubikey'),
    'google': _('Google Authenticator'),
    'generic': _('Authentication device'),
    'paper': _('Printable Backup Codes'),
}


def generate_key(n):
    """Returns an OATH/HOTP key as a string of n raw bytes."""

    # An OATH/HOTP key is just bunch of random (in the "unpredictable"
    # sense) bits, of certain quantities (e.g. 160 bits or 20 bytes)
    # that are compatible with the AES algorithms.

    # From openssl's documentation:
    #
    #   RAND_bytes() puts num cryptographically strong pseudo-random
    #   bytes into buf. An error occurs if the PRNG has not been
    #   seeded with enough randomness to ensure an unpredictable byte
    #   sequence.
    #
    # openssl's RAND_bytes(num) function is available in Python as
    # M2Crypto.Rand.rand_bytes(num).

    return b16encode(rand_bytes(n))


def get_unique_device_name_for_user(name, user):
    """Returns the name with an extra number to make it unique if it exists in
       existing_names
    """
    original_name = name
    counter = 1
    existing_names = [device.name for device in user.devices.all()]
    while name in existing_names:
        name = '%s (%d)' % (original_name, counter)
        counter += 1
    return name


@sso_login_required
@require_twofactor_enabled
@allow_only('GET')
def device_list(request):
    paper_renewals = list(request.user.paper_devices_needing_renewal)
    context = get_context(
        request, device_addition_path=reverse(DEVICE_ADDITION),
        devices=request.user.devices.all(),
        need_backup_device_warning=request.user.need_backup_device_warning,
        paper_devices_needing_renewal=paper_renewals
    )
    return render_to_response('device/list.html', context)


@sso_login_required
@require_twofactor_enabled
@allow_only('GET', 'POST')
def device_addition(request):
    if request.user.has_twofactor_devices():
        if not (twofactor.is_upgraded(request) and
                twofactor.is_fresh(request)):
            return redirect_to_login(
                request.get_full_path(),
                reverse('twofactor')
            )

    if request.method == 'GET':
        context = get_context(request, device_list_path=reverse(DEVICE_LIST))
        return render_to_response('device/types.html', context)

    device_type = request.POST.get('type')

    if device_type not in device_types.keys():
        return render_to_response('device/types.html', get_context(request))

    if device_type == 'paper':
        return _device_addition_paper(request)
    return _device_addition_standard(request, device_type)


def _device_addition_paper(request):
    hex_key = generate_key(20)
    device_name = get_unique_device_name_for_user(device_types['paper'],
                                                  request.user)
    device = _create_device(request, device_name, hex_key, 0, 'paper')
    return HttpResponseSeeOther(reverse('device-print', args=(device.id,)))


def _device_addition_standard(request, device_type):
    error = None

    if 'hex_key' in request.POST:
        hex_key = request.POST.get('hex_key')
    else:
        # TODO: 20 bytes = 160 bits; this will change based on
        # device-type.
        hex_key = generate_key(20)

    if 'name' not in request.POST:
        initial_name = get_unique_device_name_for_user(
            device_types.get(device_type), request.user)
        form = HOTPDeviceForm(initial={'name': initial_name})
    else:
        form = HOTPDeviceForm(request.POST)
        if form.is_valid():
            device_name = get_unique_device_name_for_user(
                form.cleaned_data['name'], request.user)
            otp = form.cleaned_data['otp']
            otp_type = get_otp_type(otp)
            accepted, new_counter = accept_hotp(
                hex_key, otp, 0, otp_type, drift=settings.HOTP_DRIFT,
                backward_drift=settings.HOTP_BACKWARDS_DRIFT)
            if accepted:
                _create_device(request, device_name, hex_key,
                               new_counter, device_type)
                return HttpResponseSeeOther(reverse(DEVICE_LIST))

            # Otherwise, set the error flag and fall through...
            error = OTP_MATCH_ERROR

    # Google would base32-encode, yubi would hex-encode, etc.  There
    # might even be multiple formats displayed simultaneously.
    formatted_key = re.sub('(.{4})', r'\1 ', hex_key).strip()

    ctx = get_context(
        request,
        device_list_path=reverse(DEVICE_LIST),
        type=device_type,
        ident="/".join([settings.TWOFACTOR_SERVICE_IDENT,
                        request.user.preferredemail.email]),
        hex_key=hex_key,
        form=form,
        formatted_key=formatted_key,
        error=error,
    )
    return render_to_response('device/addition-%s.html' % device_type, ctx)


def _create_device(request, device_name, hex_key, counter, device_type):
    device = AuthenticationDevice.objects.create(
        account=request.user,
        name=device_name,
        key=hex_key,
        counter=counter,
        device_type=device_type
    )
    twofactor.login(request)
    messages.success(request,
                     DEVICE_ADDED.format(name=device_name), 'temporary')
    return device


@switch_is_active('PAPER_DEVICE')
@sso_login_required(require_twofactor=True, require_twofactor_freshness=True)
@require_twofactor_enabled
@allow_only('GET')
def device_print(request, device_id):
    device = _get_device_or_404(device_id, request.user)
    if device.device_type != 'paper':
        raise Http404

    details = _codes_for_position(device)
    remaining_codes = settings.TWOFACTOR_PAPER_CODES - details.position
    generation_enabled = (
        remaining_codes <= settings.TWOFACTOR_PAPER_CODES_ALLOW_GENERATION)

    if generation_enabled:
        messages.warning(request, DEVICE_GENERATION_WARNING)

    context = get_context(
        request,
        codes=details.codes,
        counter=details.position,
        device_id=device.id,
        generation_enabled=generation_enabled,
    )
    return TemplateResponse(request, 'device/print-codes.html', context)


def _codes_for_position(device, next_page=False):
    # use integer division to round the "window" boundaries
    page_size = settings.TWOFACTOR_PAPER_CODES
    page, page_position = divmod(device.counter, page_size)
    if next_page:
        page += 1
    page_start = page * page_size
    codes = [hotp(device.key, i, 'dec6')
             for i in range(page_start, page_start + page_size)]
    return CodePageDetails(codes, page, page_start, page_position)


@switch_is_active('PAPER_DEVICE')
@sso_login_required(require_twofactor=True, require_twofactor_freshness=True)
@require_twofactor_enabled
@allow_only('GET', 'POST')
def device_generate(request, device_id):
    device = _get_device_or_404(device_id, request.user)
    if device.device_type != 'paper':
        raise Http404

    # find the next page of codes
    details = _codes_for_position(device, next_page=True)

    if request.method == 'GET':
        context = get_context(
            request,
            codes=details.codes,
            device_id=device.id,
        )
        return TemplateResponse(request, 'device/generate-codes.html', context)

    device.counter = details.start
    device.save()
    return HttpResponseRedirect(reverse('device-print', args=(device.id,)))


def _get_device_or_404(device_id, user):
    """Explicit helper function to ensure we don't forget to limit by user."""
    return get_object_or_404(AuthenticationDevice, id=device_id, account=user)


@sso_login_required(require_twofactor=True, require_twofactor_freshness=True)
@require_twofactor_enabled
@allow_only('GET', 'POST')
def device_removal(request, device_id):
    device = _get_device_or_404(device_id, request.user)

    if request.method != 'POST':
        context = get_context(request, device_list_path=reverse(DEVICE_LIST),
                              name=device.name)
        return render_to_response('device/removal.html', context)

    device.delete()

    # We should probably send an e-mail to the user stating which
    # device was removed. As a security measure, this would be much
    # stronger if bugs #784813, #784817, and #784818 were done.

    if not request.user.has_twofactor_devices():
        request.user.twofactor_required = False
        request.user.save()
        twofactor.logout(request)

    messages.success(request, DEVICE_DELETED.format(name=device.name))
    return HttpResponseSeeOther('/device-list')


class DeviceRenameView(View):
    def get(self, request, device_id):
        device = _get_device_or_404(device_id, request.user)
        form = DeviceRenameForm({'name': device.name})
        context = get_context(
            request, device_list_path=reverse(DEVICE_LIST), form=form)
        return render_to_response('device/rename.html', context)

    def post(self, request, device_id):
        device = _get_device_or_404(device_id, request.user)
        form = DeviceRenameForm(request.POST)
        if form.is_valid():
            original_name = device.name
            device.name = form.cleaned_data['name']
            device.save()
            messages.success(request,
                             DEVICE_RENAMED.format(original=original_name,
                                                   renamed=device.name))
            return HttpResponseRedirect(reverse(DEVICE_LIST))

        context = get_context(
            request, device_list_path=reverse(DEVICE_LIST), form=form)
        return render_to_response('device/rename.html', context)


device_rename = sso_login_required(
    require_twofactor=True,
    require_twofactor_freshness=True)(DeviceRenameView.as_view())


@allow_only('GET')
def device_help(request):
    if gargoyle.is_active('CAN_VIEW_SUPPORT_PHONE', request.user):
        support_phone = settings.SUPPORT_PHONE
    else:
        support_phone = ''

    context = RequestContext(request, {'support_phone': support_phone})
    return render_to_response('device/device-help.html', context)
