# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

import logging

from openid import oidutil


# Disable writing OpenID messaged to stderr
oidutil.log = logging.debug

# default api/account passwords, policy compliant
DEFAULT_API_PASSWORD = 'test'
# when changing, make sure to update test fixture with the encrypted password
DEFAULT_USER_PASSWORD = 'test1Test'
