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

import os
import pep8
import unittest
from collections import defaultdict


class Pep8ConformanceTestCase(unittest.TestCase):

    packages = []
    exclude = []

    def message(self, text):
        self.errors.append(text)

    def setUp(self):
        self.errors = {}
        self.pep8style = pep8.StyleGuide(
            counters=defaultdict(int),
            doctest='',
            exclude=self.exclude,
            filename=['*.py'],
            ignore=[],
            messages=self.errors,
            repeat=True,
            select=[],
            show_pep8=False,
            show_source=False,
            max_line_length=79,
            quiet=0,
            statistics=False,
            testsuite='',
            verbose=0
        )

    def test_pep8_conformance(self):
        for package in self.packages:
            self.pep8style.input_dir(os.path.dirname(package.__file__))
        # FIXME: When this fails, the offending lines are not displayed, they
        # should. -- vila 2012-10-19
        self.assertEqual(self.pep8style.options.report.total_errors, 0)
