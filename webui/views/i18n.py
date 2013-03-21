# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from urllib import quote, unquote

from django.conf import settings
from django.http import Http404, HttpResponseRedirect
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.core.urlresolvers import resolve, Resolver404

from identityprovider.views.server import set_language_info


def set_language(request):
    next = request.REQUEST.get('next', '/')
    if request.method == 'GET':
        context = RequestContext(request, {'next': quote(next)})
        return render_to_response('select_language.html', context)

    if request.method != 'POST':
        raise Http404()

    if not next.startswith('/'):
        next = '/'
    else:
        try:
            resolve(unquote(next))
        except Resolver404:
            next = '/'
    lang = request.POST.get('language')

    response = HttpResponseRedirect(next)
    if lang not in settings.SUPPORTED_LANGUAGES:
        raise Http404('Unsupported language')

    if request.user.is_authenticated():
        account = request.user
        account.preferredlanguage = lang
        account.save()

    set_language_info(request, response, lang)
    return response
