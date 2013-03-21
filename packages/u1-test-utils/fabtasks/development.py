# -*- coding: utf-8 -*-

# Copyright 2012, 2013 Canonical Ltd.
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License version 3, as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranties of
# MERCHANTABILITY, SATISFACTORY QUALITY, or FITNESS FOR A PARTICULAR
# PURPOSE.  See the GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import unittest


def test(suites=None):
    """Run tests.

    Keyword arguments:
    suites -- A list of test suites to run. The available suites are
        'static' and 'unit'. If none are supplied, all the known ones are run.

    """
    os.environ['DJANGO_SETTINGS_MODULE'] = \
        'u1testutils.selftests.django_project.settings'
    if suites is None:
        suites = ['static', 'unit']
    suite = unittest.TestSuite()
    # FIXME: We shouldn't need to create a new loader for each path, in fact,
    # we should be able to discover all tests with a single call even if it
    # means defining load_tests() functions in the test modules. Additionally,
    # the ``suites`` parameter should allow filtering (which we get here in an
    # ad-hoc way).  -- vila 2012-10-25
    module_paths = []
    if 'static' in suites:
        module_paths.append('u1testutils/selftests/static')
    if 'unit' in suites:
        module_paths.append('u1testutils/selftests/unit')
        module_paths.append('u1testutils/sst/sso/selftests/unit')
    for mp in module_paths:
        suite.addTest(unittest.TestLoader().discover(mp))
    # List the tests as we run them
    runner = unittest.TextTestRunner(verbosity=2)
    res = runner.run(suite)
    print 'Totals: ran({0}), skipped({1}), errors({2}), failures({3})'.format(
        res.testsRun, len(res.skipped), len(res.errors), len(res.failures))
