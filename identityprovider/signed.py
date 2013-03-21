# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

"""
Functions for creating and restoring url-safe signed pickled objects.

The format used looks like this:

>>> dumps("hello", secret="secretkey")
'UydoZWxsbycKcDAKLg.F2uusAzJLBjUqmMog4Mr21QZIFk'

There are two components here, separatad by a '.'. The first component is a
URLsafe base64 encoded pickle of the object passed to dumps(). The second
component is a base64 encoded SHA1 hash of "$first_component.$secret"

Calling signed.loads(s) checks the signature BEFORE unpickling the object -
this protects against malformed pickle attacks. If the signature fails, a
ValueError subclass is raised (actually a BadSignature):

>>> loads('UydoZWxsbycKcDAKLg.F2uusAzJLBjUqmMog4Mr21QZIFk', secret="secretkey")
'hello'
>>> loads('UydoZWxsbycKcDAKLg.F2uusAzJLBjUqmMog4Mr21QZIFk-modified')
Traceback (most recent call last):
...
BadSignature: Signature failed: F2uusAzJLBjUqmMog4Mr21QZIFk-modified

There are 65 url-safe characters: the 64 used by url-safe base64 and the '.'.
These functions make use of all of them.
"""

import base64
import hashlib
import pickle

from django.conf import settings


def dumps(obj, secret=None, extra_salt=''):
    """
    Returns URL-safe, sha1 signed base64 compressed pickle. If secret is
    None, settings.SECRET_KEY is used instead.

    extra_salt can be used to further salt the hash, in case you're worried
    that the NSA might try to brute-force your SHA-1 protected secret.
    """
    pickled = pickle.dumps(obj)
    base64d = encode(pickled).strip('=')
    return sign(base64d, (secret or settings.SECRET_KEY) + extra_salt)


def loads(s, secret=None, extra_salt=''):
    "Reverse of dumps(), raises ValueError if signature fails"
    if isinstance(s, unicode):
        s = s.encode('utf8')  # base64 works on bytestrings, not on unicodes
    try:
        base64d = unsign(s, (secret or settings.SECRET_KEY) + extra_salt)
    except ValueError:
        raise
    pickled = decode(base64d)
    return pickle.loads(pickled)


def encode(s):
    return base64.urlsafe_b64encode(s).strip('=')


def decode(s):
    return base64.urlsafe_b64decode(s + '=' * (len(s) % 4))


class BadSignature(ValueError):
    # Extends ValueError, which makes it more convenient to catch and has
    # basically the correct semantics.
    pass


def sign(value, key=None):
    if isinstance(value, unicode):
        raise TypeError(
            'sign() needs bytestring, not unicode: %s' % repr(value))
    if key is None:
        key = settings.SECRET_KEY
    return value + '.' + base64_sha1(value + key)


def unsign(signed_value, key=None):
    if isinstance(signed_value, unicode):
        raise TypeError('unsign() needs bytestring, not unicode')
    if key is None:
        key = settings.SECRET_KEY
    if not '.' in signed_value:
        raise BadSignature('Missing sig (no . found in value)')
    value, sig = signed_value.rsplit('.', 1)
    if base64_sha1(value + key) == sig:
        return value
    else:
        raise BadSignature('Signature failed: %s' % sig)


def base64_sha1(s):
    return encode(hashlib.sha1(s).digest())
