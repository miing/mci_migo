#!/usr/bin/env python
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


import paths
paths.setup_paths()

if __name__ == '__main__':
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dj.settings')

    from django_configglue.management import execute_from_command_line

    execute_from_command_line(sys.argv)
