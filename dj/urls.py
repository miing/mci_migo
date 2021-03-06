###################################################################
#
# Copyright (c) 2011 Canonical Ltd.
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

from django.conf import settings
from django.conf.urls.defaults import patterns, include
from django.contrib import admin
from django.contrib.auth.views import logout

import nexus
import preflight
from adminaudit import audit_install


admin.autodiscover()
audit_install()
nexus.autodiscover()
preflight.autodiscover()

handler500 = 'webui.views.errors.server_error'
handler404 = 'webui.views.errors.page_not_found'

urlpatterns = patterns('',
    #(r'^admin/', check_readonly(admin.site.urls)),
    (r'^preflight/', include('preflight.urls')),
    (r'^admin/', include(nexus.site.urls)),
    (r'', include('identityprovider.urls')),
    # Web UI
    (r'', include('webui.urls')),
    # Lazr.restful backwards compatible api
    (r'^api/', include('api.urls')),
    # SAML support
    (r'^\+saml', include('saml2sso.urls')),

    # OpenID views
    (r'^openid/', include('django_openid_auth.urls')),
    (r'^logout/$', logout, {'next_page': '/'}),
)
