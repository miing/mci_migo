# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from django import template
from django.conf import settings

register = template.Library()


@register.filter
def static_url(url_name):
    return getattr(settings, '%s_URL' % url_name.upper(), '')
