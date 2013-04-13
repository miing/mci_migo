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
        'static', 'unit' and 'acceptance'. If none are supplied, all the
        known ones are run.

    """
    os.environ['DJANGO_SETTINGS_MODULE'] = \
        'u1testutils.selftests.django_project.settings'
    if suites is None:
        suites = ['static', 'unit', 'acceptance']
    # FIXME: We shouldn't need to create a new loader for each path, in fact,
    # we should be able to discover all tests with a single call even if it
    # means defining load_tests() functions in the test modules. Additionally,
    # the ``suites`` parameter should allow filtering (which we get here in an
    # ad-hoc way).  -- vila 2012-10-25
    suite = unittest.TestSuite()
    if 'static' in suites:
        suite = _load_static_tests(suite)
    if 'unit' in suites:
        suite = _load_unit_tests(suite)        
    if 'acceptance' in suites:
        suite = _load_acceptance_tests(suite)
    # List the tests as we run them
    runner = unittest.TextTestRunner(verbosity=2)
    res = runner.run(suite)
    print 'Totals: ran({0}), skipped({1}), errors({2}), failures({3})'.format(
        res.testsRun, len(res.skipped), len(res.errors), len(res.failures))


def _load_static_tests(suite):
    suite.addTest(
        unittest.TestLoader().discover('u1testutils/selftests/static'))
    return suite


def _load_unit_tests(suite):
    for path in (
            'u1testutils/selftests/unit',
            'u1testutils/sst/selftests/unit',
            'u1testutils/sso/selftests/unit',
            'u1testutils/pay/selftests/unit',
            ):
        suite.addTest(unittest.TestLoader().discover(path))
    return suite


def _load_acceptance_tests(suite):
    suite.addTest(
        unittest.TestLoader().discover('u1testutils/sst/selftests/acceptance'))
    return suite
