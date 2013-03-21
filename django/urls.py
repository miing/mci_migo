from django.conf import settings
from django.conf.urls.defaults import *
from django.contrib import admin
from django.contrib.auth.views import logout

import nexus
import preflight
from adminaudit import audit_install

from webui.decorators import check_readonly

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
    (r'^\+saml', include('ubuntu_sso_saml.urls')),

    # OpenID views
    (r'^openid/', include('django_openid_auth.urls')),
    (r'^logout/$', logout, {'next_page': '/'}),
)

if settings.SERVE_STATIC_MEDIA:
    urlpatterns += patterns('',
        (r'assets/identityprovider/(.*)', 'django.views.static.serve',
            {'document_root': settings.SSO_MEDIA_ROOT}),
        (r'media/(.*)', 'django.views.static.serve',
            {'document_root': settings.MEDIA_ROOT}),
)
