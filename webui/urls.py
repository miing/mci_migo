# Copyright 2010, 2012 Canonical Ltd.  This software is licensed under
# the GNU Affero General Public License version 3 (see the file
# LICENSE).

from django.conf.urls.defaults import *

from identityprovider.models import AUTHTOKEN_PATTERN
from webui.views.ui import LoginView, TwoFactorView


repls = {
    'token': '(?P<token>[A-Za-z0-9]{16})/',
    'authtoken': '(?P<authtoken>%s)' % AUTHTOKEN_PATTERN,
    'email_address': '(?P<email_address>.+)'
}

twofactor = TwoFactorView.as_view()
login = LoginView.as_view()

urlpatterns = patterns(
    'webui.views.ui',
    # Django's URL-reversing doesn't like to play with regex
    # alternates '|' or optionals '?'.  Named parameters in such
    # clauses get clobbered to such names as '_0'.  Breaking out the
    # combinations ourselves ensures the names are maintained.
    url(r'^\+login$', login, name='login'),
    url(r'^%(token)s\+login$' % repls, login, name='login'),

    url(r'^\+logout$' % repls, 'logout', name='logout'),
    url(r'^%(token)s\+logout$' % repls, 'logout', name='logout'),

    url(r'^two_factor_auth$', twofactor, name='twofactor'),
    url(r'^%(token)stwo_factor_auth$' % repls, twofactor, name='twofactor'),

    url(r'^\+new_account$' % repls, 'new_account', name='new_account'),
    url(r'^%(token)s\+new_account$' % repls, 'new_account',
        name='new_account'),

    url(r'^\+forgot_password$' % repls, 'forgot_password',
        name='forgot_password'),
    url(r'^%(token)s\+forgot_password$' % repls, 'forgot_password',
        name='forgot_password'),

    url(r'^\+enter_token$' % repls, 'enter_token', name='enter_token'),
    url(r'^%(token)s\+enter_token$' % repls, 'enter_token',
        name='enter_token'),

    url(r'^token/%(authtoken)s/$' % repls, 'claim_token', name='claim_token'),

    url(r'^token/%(authtoken)s/\+resetpassword/%(email_address)s$' % repls,
        'reset_password', name='reset_password'),
    url(r'^%(token)stoken/%(authtoken)s/\+resetpassword/%(email_address)s$'
        % repls, 'reset_password', name='reset_password'),

    url(r'^token/%(authtoken)s/\+newaccount/%(email_address)s$' % repls,
        'old_confirm_account'),
    url(r'^confirm-account/%(authtoken)s/%(email_address)s$' % repls,
        'confirm_account', name='confirm_account'),
    url(r'^%(token)sconfirm-account/%(authtoken)s/%(email_address)s$' % repls,
        'confirm_account', name='confirm_account'),

    url(r'^token/%(authtoken)s/\+newemail/%(email_address)s$' % repls,
        'confirm_email', name='confirm_email'),
    url(r'^%(token)stoken/%(authtoken)s/\+newemail/%(email_address)s$' % repls,
        'confirm_email', name='confirm_email'),
    url(r'^\+bad-token', 'bad_token', name='bad_token'),
    url(r'^\+logout-to-confirm', 'logout_to_confirm',
        name='logout_to_confirm'),
    url(r'^\+deactivated$', 'deactivated', name='deactivated'),
    url(r'^\+suspended$', 'suspended', name='suspended'),
    url(r'^\+description$', 'static_page', {'page_name': 'description'},
        name='description'),
    url(r'^\+faq$', 'static_page', {'page_name': 'faq'}, name='faq'),
    url(r'^\+ubuntuone-account$', 'static_page',
        {'page_name': 'ubuntuone-account'}, name='ubuntuone-account'),

)

urlpatterns += patterns(
    'webui.views.account',
    url(r'^$', 'index', name='account-index'),
    url(r'^%(token)s$' % repls, 'index', name='account-index'),
    url(r'^\+emails$', 'account_emails', name='account-emails'),
    url(r'^\+edit$', 'account_edit', name='account-edit'),
    url(r'^%(token)s\+edit$' % repls, 'index', name='account-edit'),
    url(r'^\+cookie$', 'cookie'),
    url(r'^\+index$' % repls, 'index', name='index'),
    url(r'^%(token)s\+index$' % repls, 'index', name='index'),
    url(r'^\+new-email$' % repls, 'new_email', name='new_email'),
    url(r'^%(token)s\+new-email$' % repls, 'new_email', name='new_email'),
    url(r'^\+verify-email$' % repls, 'verify_email', name='verify_email'),
    url(r'^%(token)s\+verify-email$' % repls, 'verify_email',
        name='verify_email'),
    url(r'^invalidate-email/%(authtoken)s/%(email_address)s$' % repls,
        'invalidate_email', name='invalidate_email'),
    url(r'^\+remove-email$' % repls, 'delete_email', name='delete_email'),
    url(r'^%(token)s\+remove-email$' % repls, 'delete_email',
        name='delete_email'),
    url(r'^\+applications$', 'applications', name='applications'),
    url(r'^\+deactivate$', 'account_deactivate', name='account_deactivate'),
    url(r'^%(token)s\+deactivate$' % repls, 'account_deactivate',
        name='account_deactivate'),
)

# TODO: Support the login-tokens, if it makes sense.
urlpatterns += patterns(
    'webui.views.devices',
    url(r'^device-list$', 'device_list', name='device-list'),
    url(r'^device-addition$', 'device_addition', name='device-addition'),
    url(r'^device-removal/(?P<device_id>.+)$', 'device_removal',
        name='device-removal'),
    url(r'^device-rename/(?P<device_id>.+)$', 'device_rename',
        name='device-rename'),
    url(r'^\+device-help$', 'device_help', name='device-help'),
    url(r'^device-print/(?P<device_id>.+)$', 'device_print',
        name='device-print'),
    url(r'^device-generate/(?P<device_id>.+)$', 'device_generate',
        name='device-generate'),
)

urlpatterns += patterns(
    'webui.views.i18n',
    url(r'^set_language$', 'set_language', name='set_language'),
)

urlpatterns += patterns(
    'webui.views.readonly',
    url(r'^readonly$', 'readonly_admin'),
    url(r'^readonly/((?P<appserver>[A-Za-z0-9\-_.:]+)/)?'
        r'(?P<action>enable|disable|set|clear)(/(?P<conn>[A-Za-z0-9\-_.]+))?',
        'readonly_confirm'),
    url(r'^readonlydata$', 'readonly_data'),
)

urlpatterns += patterns(
    'webui.views.consumer',
    url(r'^consumer/$', 'start_open_id', name='start_open_id'),
    url(r'^consumer/finish/$', 'finish_open_id', name='finish_open_id'),
    url(r'^consumer/xrds/$', 'rpXRDS', name='rp_xrds'),
)
