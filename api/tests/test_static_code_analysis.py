from u1testutils.static import (
    test_pep8_conformance,
    test_pyflakes_analysis,
)

import api


class ApiPep8TestCase(test_pep8_conformance.Pep8ConformanceTestCase):
    exclude = ['migrations']
    packages = [api]


class ApiPyFlakesTestCase(test_pyflakes_analysis.PyflakesAnalysisTestCase):
    packages = [api]
    exclude_file = 'tools/pyflakes.txt'
