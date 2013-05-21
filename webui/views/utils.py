# Copyright 2010, 2012 Canonical Ltd.  This software is licensed under
# the GNU Affero General Public License version 3 (see the file
# LICENSE).

from functools import wraps

from django.conf import settings
from django.http import HttpResponseNotAllowed, HttpResponseRedirect
from django.template.response import TemplateResponse


class HttpResponseSeeOther(HttpResponseRedirect):
    status_code = 303


def allow_only(*methods):
    def decorator(fn):
        @wraps(fn)
        def wrapper(request, *args, **kwargs):
            if request.method not in methods:
                return HttpResponseNotAllowed(methods)
            return fn(request, *args, **kwargs)
        return wrapper
    return decorator


def display_email_sent(request, email, heading, reason, extra=None, token=None,
                       rpconfig=None):
    context = {
        'email_feedback': settings.FEEDBACK_TO_ADDRESS,
        'email_heading': heading,
        'email_reason': reason,
        'email_notreceived_extra': extra,
        'email': email,
        'token': token,
        'rpconfig': rpconfig,
    }
    return TemplateResponse(request, 'registration/email_sent.html', context)


def set_session_email(session, email):
    """Place information about the current token's email in the session"""
    session['token_email'] = email


def add_captcha_settings(context):
    d = {'CAPTCHA_PUBLIC_KEY': settings.CAPTCHA_PUBLIC_KEY,
         'CAPTCHA_API_URL_SECURE': settings.CAPTCHA_API_URL_SECURE}
    d.update(context)
    return d
