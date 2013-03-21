# Copyright 2011 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from .database import *
from .deployment import *
from .development import *
from .django import *
from .environment import *

# make sure the virtualenv is automatically activated
setup_virtualenv()
