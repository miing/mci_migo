# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

import functools
import logging

from datetime import datetime, timedelta
from functools import wraps
from hashlib import sha1

from django.contrib.auth import REDIRECT_FIELD_NAME, logout
from django.contrib.auth.decorators import (
    login_required as django_login_required,
)
from django.conf import settings
from django.contrib.auth.views import redirect_to_login
from django.core.cache import cache
from django.core.urlresolvers import reverse
from django.http import (
    Http404,
    HttpResponseForbidden,
    HttpResponseRedirect,
)
from django.template import RequestContext
from django.template.loader import render_to_string
from django.template.response import TemplateResponse
from django.utils.decorators import available_attrs
from django.utils.http import urlencode

from identityprovider.cookies import set_test_cookie, test_cookie_worked
from identityprovider.models import twofactor
from identityprovider.views.utils import get_rpconfig_from_request


def guest_required(func):
    @functools.wraps(func)
    def _guest_required_decorator(request, *args, **kwargs):
        if request.user.is_authenticated():
            return HttpResponseRedirect('/')
        else:
            return func(request, *args, **kwargs)
    return _guest_required_decorator


def dont_cache(func):
    def _dont_cache_decorator(request, *args, **kwargs):
        response = func(request, *args, **kwargs)
        response["Expires"] = "Tue, 03 Jul 2001 06:00:00 GMT"
        response["Cache-Control"] = ("no-store, no-cache, "
                                     "must-revalidate, max-age=0")
        response['Pragma'] = 'no-cache'
        return response
    return _dont_cache_decorator


def _has_only_invalidated_emails(request):
    # user has *zero* usable email addresses, log him/her out
    if request.user.emailaddress_set.count() == 0:
        logout(request)
        return TemplateResponse(
            request, 'account/user_logged_out_no_valid_emails.html')


def sso_login_required(function=None, redirect_field_name=REDIRECT_FIELD_NAME,
                       login_url=None, require_twofactor=False,
                       require_twofactor_freshness=False):
    """Wrap up django's login_required, and also checks for 2f."""

    def decorator(view_func):

        @wraps(view_func, assigned=available_attrs(view_func))
        def _wrapped_view(request, *args, **kwargs):
            response = _has_only_invalidated_emails(request)
            if response:
                return response

            rpconfig = get_rpconfig_from_request(request, None)
            u = request.user
            required = (
                require_twofactor or
                twofactor.user_requires_twofactor_auth(request, u) or
                twofactor.site_requires_twofactor_auth(request, None, rpconfig)
            )
            require_auth = (
                (required and not twofactor.is_upgraded(request)) or
                (require_twofactor_freshness and
                 not twofactor.is_fresh(request))
            )
            if require_auth:
                # only valid reverse arg is token
                reverse_args = {}
                if 'token' in kwargs and kwargs['token'] is not None:
                    reverse_args['token'] = kwargs['token']
                return redirect_to_login(
                    request.get_full_path(),
                    reverse('twofactor', kwargs=reverse_args),
                    redirect_field_name,
                )
            return view_func(request, *args, **kwargs)

        return django_login_required(
            _wrapped_view, redirect_field_name, login_url,
        )

    if function:
        return decorator(function)
    return decorator


def check_readonly(func):
    """A readonly aware decorator.

    The decorated view will not be accessible at all during readonly mode.
    Instead, a static warning page will be displayed.
    """

    def wrapper(request, *args, **kwargs):
        if settings.READ_ONLY_MODE:
            html = render_to_string(
                'readonly.html',
                {'readonly': False},
                context_instance=RequestContext(request)
            )
            return HttpResponseForbidden(html)
        return func(request, *args, **kwargs)

    functools.update_wrapper(wrapper, func)
    return wrapper


disable_cookie_check = False


def requires_cookies(func):
    @functools.wraps(func)
    def wrapper(request, *args, **kwargs):
        if disable_cookie_check or test_cookie_worked(request):
            return func(request, *args, **kwargs)
        quoted = urlencode({'next': request.get_full_path()})
        return set_test_cookie(HttpResponseRedirect('/+cookie?' + quoted))
    return wrapper


def require_twofactor_enabled(func):
    @wraps(func)
    def wrapped(request, *args, **kwargs):
        if not twofactor.is_twofactor_enabled(request):
            raise Http404('Switch \'TWOFACTOR\' is not active')
        return func(request, *args, **kwargs)
    return wrapped


def requires_testing_enabled(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        if not getattr(settings, 'TESTING', False):
            raise Http404()
        return func(*args, **kwargs)
    return wrapped


class ratelimit(object):
    """ A rate-limiting decorator.
        Strongly based on Simon Willison's code,
        http://github.com/simonw/ratelimitcache/blob/master/ratelimitcache.py
    """
    # This class is designed to be sub-classed
    minutes = 2  # The time period
    requests = 20  # Number of allowed requests in that time period

    prefix = 'rl-'  # Prefix for memcache key

    def __init__(self, **options):
        # explicitly setting the name to pretend we're a function to allow this
        # decorator to work like with django's method_decorator function
        self.__name__ = self.__class__.__name__
        for key, value in options.items():
            setattr(self, key, value)

    def __call__(self, fn):
        def wrapper(request, *args, **kwargs):
            return self.view_wrapper(request, fn, *args, **kwargs)
        functools.update_wrapper(wrapper, fn)
        return wrapper

    def view_wrapper(self, request, fn, *args, **kwargs):
        if not self.should_ratelimit(request):
            return fn(request, *args, **kwargs)

        counts = self.get_counters(request).values()
        # Increment rate limiting counter
        self.cache_incr(self.current_key(request))

        # Have they failed?
        if sum(int(x) for x in counts) >= self.requests:
            return self.disallowed(request)

        return fn(request, *args, **kwargs)

    def cache_get_many(self, keys):
        return cache.get_many(keys)

    def cache_incr(self, key):
        # memcache is only backend that can increment atomically
        try:
            # add first, to ensure the key exists
            cache.add(key, 0, timeout=self.expire_after())
            cache.incr(key)
        except AttributeError:
            cache.set(key, cache.get(key, 0) + 1, self.expire_after())

    def should_ratelimit(self, request):
        return True

    def get_counters(self, request):
        return self.cache_get_many(self.keys_to_check(request))

    def keys_to_check(self, request):
        extra = self.key_extra(request)
        now = datetime.utcnow()
        return [
            '%s%s-%s' % (
                self.prefix,
                extra,
                (now - timedelta(minutes=minute)).strftime('%Y%m%d%H%M')
            ) for minute in range(self.minutes + 1)
        ]

    def current_key(self, request):
        return '%s%s-%s' % (
            self.prefix,
            self.key_extra(request),
            datetime.utcnow().strftime('%Y%m%d%H%M')
        )

    def remote_ip(self, request):
        if 'HTTP_X_FORWARDED_FOR' in request.META:
            remote_ip = request.META['HTTP_X_FORWARDED_FOR']
            # Because X-Forwarded-For can be a list of IP's we need only one
            remote_ip = remote_ip.split(',')[0].strip()
        else:
            remote_ip = request.META.get('REMOTE_ADDR')
        return remote_ip

    def key_extra(self, request):
        # By default, their IP address is used
        return self.remote_ip(request)

    def disallowed(self, request):
        remote_ip = self.remote_ip(request)
        logger = logging.getLogger('ratelimit.disallowed')

        def _get_name(user):
            try:
                return user.openid_identifier
            except AttributeError:
                return user.username
        logger.warn("%s (%s) exceeded rate limit for %s",
                    _get_name(request.user), remote_ip, request.user.id)
        return HttpResponseForbidden(render_to_string('limitexceeded.html'))

    def expire_after(self):
        "Used for setting the memcached cache expiry"
        return (self.minutes + 1) * 60

    def reset_count(self, request):
        "Reset the rate limiting limit count for a request"
        for key in self.keys_to_check(request):
            cache.delete(key)


class ratelimit_post(ratelimit):
    "Rate limit POSTs - can be used to protect a login form"
    key_field = None  # If provided, this POST var will affect the rate limit

    def should_ratelimit(self, request):
        return request.method == 'POST'

    def key_extra(self, request):
        # IP address and key_field (if it is set)
        extra = super(ratelimit_post, self).key_extra(request)
        if self.key_field:
            value = sha1(request.POST.get(self.key_field, '').encode('utf-8'))
            extra += '-' + value.hexdigest()
        return extra


class limitlogin(ratelimit_post):
    """Limit login POSTs, per username.

    Also, take default values from settings.
    """
    key_field = 'email'

    def __init__(self, **options):
        args = {
            'minutes': getattr(settings, 'LOGIN_LIMIT_MINUTES', 2),
            'requests': getattr(settings, 'LOGIN_LIMIT_REQUESTS', 20),
        }
        args.update(options)
        super(limitlogin, self).__init__(**args)
