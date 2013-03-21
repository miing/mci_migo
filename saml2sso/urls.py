# Copyright 2012 Canonical Ltd. This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).
from django.conf.urls.defaults import *
from saml2idp.urls import deeplink_url_patterns


urlpatterns = patterns(
    'ubuntu_sso_saml.views',
    url(r'^$', 'saml_begin', name='login_begin'),
    url(r'^/process$', 'saml_process', name='login_process'),
)


# Automagically detect deep link URLs from settings:
urlpatterns += deeplink_url_patterns(
    'ubuntu_sso_saml.views',
    r'^/init/%s$', 'saml_init'
)
