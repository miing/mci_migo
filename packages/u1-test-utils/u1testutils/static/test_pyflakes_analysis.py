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
import unittest
import cStringIO

from mock import patch
from pyflakes.scripts.pyflakes import checkPath


class PyflakesAnalysisTestCase(unittest.TestCase):

    packages = []
    exclude_file = None

    def test_pyflakes_analysis(self):
        string_out = cStringIO.StringIO()
        with patch('sys.stdout', string_out):
            for package in self.packages:
                self._run_pyflakes_analysis(package)
        results = string_out.getvalue().splitlines()
        unexpected_errors = self._get_unexpected_errors(results)
        self.assertEqual(unexpected_errors, [],
                         '\n'.join(unexpected_errors))

    def _run_pyflakes_analysis(self, package):
        package_path = os.path.dirname(package.__file__)
        for dir_path, dir_names, file_names in os.walk(package_path):
            for file_name in file_names:
                if file_name.endswith('.py'):
                    file_path = os.path.join(dir_path, file_name)
                    checkPath(file_path)

    def _get_unexpected_errors(self, results):
        unexpected_errors = []
        expected_errors = self._parse_exclude_file()
        if not expected_errors:
            unexpected_errors = results
        else:
            for line in results:
                found = False
                for file_, error in expected_errors:
                    if file_ in line and error in line:
                        found = True
                        break
                if not found:
                    unexpected_errors.append(line)
        return unexpected_errors

    def _parse_exclude_file(self):
        excluded_errors = []
        if self.exclude_file is not None:
            with open(self.exclude_file) as file_:
                for line in file_:
                    if line.strip():
                        source_file, error = [data.strip() for data in
                                              line.split(':', 1)]
                        excluded_errors.append((source_file, error))
        return excluded_errors
