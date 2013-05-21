# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from functools import wraps

from django.http import HttpResponseForbidden

from identityprovider.models import (
    Account,
    APIUser,
)


def api_user_required(func):
    @wraps(func)
    def wrapper(self, request, *args, **kwargs):
        user = request.user
        if user:
            if isinstance(user, APIUser):
                return func(self, request, *args, **kwargs)
        response = HttpResponseForbidden('403 Forbidden')
        # Added back bit required by django-piston
        response._is_string = True
        return response
    return wrapper


def plain_user_required(func):
    @wraps(func)
    def wrapper(self, request, *args, **kwargs):
        user = request.user
        if user:
            if isinstance(user, Account):
                return func(self, request, *args, **kwargs)
        response = HttpResponseForbidden('403 Forbidden')
        # Added back bit required by django-piston
        response._is_string = True
        return response
    return wrapper


def named_operation(func):
    func.is_named_operation = True
    return func
