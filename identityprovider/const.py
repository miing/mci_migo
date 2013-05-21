# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from openid.message import NamespaceMap

LAUNCHPAD_TEAMS_NS = 'http://ns.launchpad.net/2007/openid-teams'

SESSION_TOKEN_KEY = 'session_token'
SESSION_TOKEN_NAME = 'Web Login'

PERSON_VISIBILITY_PUBLIC = 1
PERSON_VISIBILITY_PRIVATE_MEMBERSHIP = 20
PERSON_VISIBILITY_PRIVATE = 30

SREG_DATA_FIELDS_ORDER = [
    'fullname', 'nickname', 'email', 'timezone',
    'x_address1', 'x_address2', 'x_city', 'x_province',
    'country', 'postcode', 'x_phone', 'x_organization', 'language'
]

SREG_LABELS = {
    'nickname': 'Username',
    'fullname': ' Full name',
    'email': 'Email address',
    'timezone': 'Time zone',
    'language': 'Preferred language',
}

AX_URI_FULL_NAME = 'http://axschema.org/namePerson'
AX_URI_NICKNAME = 'http://axschema.org/namePerson/friendly'
AX_URI_EMAIL = 'http://axschema.org/contact/email'
AX_URI_TIMEZONE = 'http://axschema.org/timezone'
AX_URI_LANGUAGE = 'http://axschema.org/language/pref'
AX_URI_ACCOUNT_VERIFIED = 'http://ns.login.ubuntu.com/2013/validation/account'

AX_DATA_FIELDS = NamespaceMap()
AX_DATA_FIELDS.addAlias(AX_URI_FULL_NAME, 'fullname')
AX_DATA_FIELDS.addAlias(AX_URI_NICKNAME, 'nickname')
AX_DATA_FIELDS.addAlias(AX_URI_EMAIL, 'email')
AX_DATA_FIELDS.addAlias(AX_URI_TIMEZONE, 'timezone')
AX_DATA_FIELDS.addAlias(AX_URI_LANGUAGE, 'language')
AX_DATA_FIELDS.addAlias(AX_URI_ACCOUNT_VERIFIED, 'account_verified')

AX_DATA_LABELS = {
    'fullname': 'Full name',
    'nickname': 'Username',
    'email': 'Email address',
    'timezone': 'Time zone',
    'language': 'Preferred language',
    'account_verified': 'Account verified',
}
