# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from base64 import b32encode
from urllib import quote
from django import template

register = template.Library()
URL = 'https://chart.googleapis.com/chart?chs=250x250&chld=L|0&cht=qr&chl=%s'


def _encode(s):
    return b32encode(s.decode('HEX'))


@register.filter
def b32encode_hexstring(value):
    return _encode(value)


@register.simple_tag
def qrcode_url(ident, hex_key):
    b32_key = _encode(hex_key)
    otp_url = 'otpauth://hotp/%s?secret=%s&counter=0' % (ident, b32_key)
    # note: for https, you *must* use this domain
    return URL % quote(otp_url)
