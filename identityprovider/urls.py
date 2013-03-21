# Copyright 2010, 2012 Canonical Ltd.  This software is licensed under
# the GNU Affero General Public License version 3 (see the file
# LICENSE).

from django.conf.urls.defaults import *
from django.conf import settings


repls = {
    'token': '(?P<token>[A-Za-z0-9]{16})/',
}

urlpatterns = patterns(
    'identityprovider.views.server',
    (r'^((?P<lang>[A-Za-z_]+)/)?\+openid$', 'openid_provider'),
    (r'^\+xrds$', 'xrds'),
    (r'^\+id/(?P<identifier>[A-Za-z0-9\-_]+)$', 'identity_page'),
    (r'^\+id/(?P<identifier>[A-Za-z0-9\-_]+)/\+xrds$', 'xrds_identity_page'),
    url(r'^%(token)s\+decide$' % repls, 'decide', name='server-decide'),
    url(r'^%(token)s\+cancel$' % repls, 'cancel', name='cancel'),
    (r'^%(token)s\+untrusted$' % repls, 'untrusted'),
    (r'\+pre-authorize-rp$', 'pre_authorize'),
    url(r'^login_by_token$', 'login_by_token', name='login_by_token'),
)

urlpatterns += patterns(
    'django.views.generic.simple',
    (r'^%(token)s$' % repls, 'redirect_to',
     {'url': '/%(token)s/+decide', 'permanent': False}),
    (r'^\+id/(?P<identifier>[A-Za-z0-9\-_]+)/\+index$', 'redirect_to',
     {'url': '/+id/%(identifier)s', 'permanent': False}),
)

if settings.DEBUG:
    urlpatterns += patterns(
        'identityprovider.views.testing',
        url(r'^\+openid-consumer', 'openid_consumer', name='openid_consumer'),
        url(r'^~(?P<username>[A-Za-z0-9\-_]+)(/(?P<version>[1|2]))?$',
            'delegate_profile'),
        url(r'^error$', 'error'),
    )
    urlpatterns += patterns(
        '',
        (r'(favicon.ico)', 'django.views.static.serve',
            {'document_root': settings.SSO_MEDIA_ROOT +
             settings.BRAND_TEMPLATE_DIR}),
        (r'^i18n/', include('django.conf.urls.i18n')),
    )

if getattr(settings, 'TESTING', False):
    urlpatterns += patterns(
        'identityprovider.views.testing',
        (r'^dummy$', 'dummy'),
    )
