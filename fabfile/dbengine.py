###################################################################
#
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


from .postgresql import pgsql_*
from .django import syncdb grantuser


def setup_pgsql_database():
	"""Setup PostgreSQL database"""
	pgsql_createuser()
	pgsql_createdb()
	syncdb()
	grantuser()
	
	
def drop_pgsql_database():
	"""Clean PostgreSQL database"""
	pgsql_dropdb()
	pgsql_dropuser()
