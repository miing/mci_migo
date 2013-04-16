# -*- coding: utf-8 -*-
# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

"""
Request processors return dictionaries to be merged into a
template context. Each function takes the request object as its only parameter
and returns a dictionary to add to the context.

These are referenced from the setting TEMPLATE_CONTEXT_PROCESSORS and used by
RequestContext.
"""

import datetime

from django.conf import settings
from django.core import context_processors

import identityprovider.signed as signed
from identityprovider.utils import get_current_brand


def readonly(request):
    return {'readonly': settings.READ_ONLY_MODE}


def i18n(request):
    supported = [(x, settings.LANGUAGE_NAMES[x])
                 for x in settings.SUPPORTED_LANGUAGES]
    return {'supported_languages': supported}


def detect_embedded(request):
    """Determine if this request should be rendered using the embedded theme.

    For now, just check if this request is associated to a particular
    trust root.
    """
    embedded_trust_root = getattr(settings, 'EMBEDDED_TRUST_ROOT', 'invalid')
    trust_root = None
    token = getattr(request, 'token', None)
    if token is not None:
        try:
            raw_orequest = request.session.get(token, None)
            orequest = signed.loads(raw_orequest, settings.SECRET_KEY)
            trust_root = orequest.trust_root
        except:
            pass

    result = {'embedded': embedded_trust_root == trust_root}
    return result


def google_analytics_id(request):
    """Adds the google analytics id to the context if it's present."""
    return {
        'google_analytics_id': getattr(settings, 'GOOGLE_ANALYTICS_ID', None),
    }


def current_date(request):
    return {'current_date': datetime.datetime.utcnow()}


def debug(request):
    # override the core processor to avoid depending on the request
    try:
        context_extras = context_processors.debug(request)
    except AttributeError:
        context_extras = {}
    return context_extras


def branding(request=None):
    brand = get_current_brand()
    return {
        'brand': brand,
        'brand_description': settings.BRAND_DESCRIPTIONS.get(brand, ''),
    }


def combine(request):
    return {
        'combine': settings.COMBINE,
        'combo_url': settings.COMBO_URL,
    }
