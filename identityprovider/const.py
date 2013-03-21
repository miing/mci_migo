# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

LAUNCHPAD_TEAMS_NS = 'http://ns.launchpad.net/2007/openid-teams'

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
