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

import os

from django_configglue.utils import configglue

from identityprovider.schema import schema


# get location of local cfg files
local_configs = os.environ.get('CONFIGGLUE_LOCAL_CONFIG', 'local.cfg')

# get absolute path for config files
current_dir = os.path.dirname(os.path.abspath(__file__))
config_files = map(lambda x: os.path.join(current_dir, x),
                   ['config/main.cfg'] + local_configs)

# glue everything together
configglue(schema, config_files, __name__)
