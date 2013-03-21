# -*- coding: utf-8 -*-

# Copyright 2012 Canonical Ltd.
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

import u1testutils

from u1testutils.static import (
    test_pep8_conformance,
    test_pyflakes_analysis,
)


class Pep8ConformanceTestCase(
        test_pep8_conformance.Pep8ConformanceTestCase):

    packages = [u1testutils]


class PyflakesAnalysisTestCase(
        test_pyflakes_analysis.PyflakesAnalysisTestCase):

    packages = [u1testutils]
