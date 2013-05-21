# Copyright 2010, 2012 Canonical Ltd.  This software is licensed under
# the GNU Affero General Public License version 3 (see the file
# LICENSE).

from django.conf.urls import include, patterns, url
from django.conf import settings
from django.views.generic import RedirectView


repls = {
    'token': '(?P<token>[A-Za-z0-9]{16})/',
}

urlpatterns = patterns(
    'identityprovider.views.server',
    url(r'^\+openid$', 'openid_provider', name='server-openid'),
    url(r'^(?P<lang>[A-Za-z_]+)/\+openid$', 'openid_provider',
        name='server-openid'),
    url(r'^\+xrds$', 'xrds'),
    url(r'^\+id/(?P<identifier>[A-Za-z0-9\-_]+)$', 'identity_page',
        name='server-identity'),
    url(r'^\+id/(?P<identifier>[A-Za-z0-9\-_]+)/\+xrds$',
        'xrds_identity_page', name='server-xrds'),
    url(r'^%(token)s\+decide$' % repls, 'decide', name='server-decide'),
    url(r'^%(token)s\+cancel$' % repls, 'cancel', name='cancel'),
    url(r'^%(token)s\+untrusted$' % repls, 'untrusted'),
    url(r'\+pre-authorize-rp$', 'pre_authorize'),
    url(r'^login_by_token$', 'login_by_token', name='login_by_token'),
)

urlpatterns += patterns(
    '',
    (r'^%(token)s$' % repls,
     RedirectView.as_view(url='/%(token)s/+decide', permanent=False)),
    (r'^\+id/(?P<identifier>[A-Za-z0-9\-_]+)/\+index$',
     RedirectView.as_view(url='/+id/%(identifier)s', permanent=False)),
)

if settings.DEBUG:
    urlpatterns += patterns(
        '',
        (r'(favicon.ico)', 'django.views.static.serve',
            {'document_root': settings.SSO_MEDIA_ROOT +
             settings.BRAND}),
        (r'^i18n/', include('django.conf.urls.i18n')),
    )

# if settings.TESTING is not set, these will raise 404
urlpatterns += patterns(
    'identityprovider.views.testing',
    url(r'^\+openid-consumer', 'openid_consumer',
        name='testing-openid-consumer'),
    url(r'^~(?P<username>[A-Za-z0-9\-_]+)$',
        'delegate_profile', name='testing-delegate-profile'),
    url(r'^~(?P<username>[A-Za-z0-9\-_]+)/(?P<version>[1|2])$',
        'delegate_profile', name='testing-delegate-profile'),
    url(r'^error$', 'error', name='testing-error'),
)
