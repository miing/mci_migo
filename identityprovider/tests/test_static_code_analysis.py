from u1testutils.static import (
    test_pep8_conformance,
    test_pyflakes_analysis,
)

import acceptance
import identityprovider


class IdentityProviderPep8TestCase(
        test_pep8_conformance.Pep8ConformanceTestCase):

    exclude = ['migrations']
    packages = [identityprovider, acceptance]


class PyFlakesTestCase(test_pyflakes_analysis.PyflakesAnalysisTestCase):

    packages = [identityprovider, acceptance]
    exclude_file = 'tools/pyflakes.txt'
