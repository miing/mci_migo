###################################################################
#
# Copyright (c) 2012 Canonical Ltd.
# Copyright (c) 2013 Miing.org <samuel.miing@gmail.com>
# 
# This software is licensed under the GNU Affero General Public 
# License version 3 (AGPLv3), as published by the Free Software 
# Foundation, and may be copied, distributed, and modified under 
# those terms.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# file LICENSE for more details.
#
###################################################################

from django.conf.urls.defaults import *
from saml2idp.urls import deeplink_url_patterns


urlpatterns = patterns(
    'saml2sso.views',
    url(r'^$', 'saml_begin', name='login_begin'),
    url(r'^/process$', 'saml_process', name='login_process'),
)

# Automagically detect deep link URLs from settings:
urlpatterns += deeplink_url_patterns(
    'saml2sso.views',
    r'^/init/%s$', 'saml_init'
)
