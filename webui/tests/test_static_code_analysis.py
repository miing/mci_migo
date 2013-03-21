from u1testutils.static import (
    test_pep8_conformance,
    test_pyflakes_analysis,
)

import webui


class WebUIPep8TestCase(test_pep8_conformance.Pep8ConformanceTestCase):
    exclude = ['migrations']
    packages = [webui]


class WebUIPyFlakesTestCase(test_pyflakes_analysis.PyflakesAnalysisTestCase):
    packages = [webui]
    exclude_file = 'tools/pyflakes.txt'
