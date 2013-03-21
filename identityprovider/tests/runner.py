from django.test.simple import reorder_suite
from django.utils.unittest import TestCase
from discover_runner.runner import DiscoverRunner
from django_jenkins import signals
from django_jenkins.runner import CITestSuiteRunner

from gargoyle import gargoyle


class IsolatedTestRunner(DiscoverRunner):

    def setup_test_environment(self, *args, **kwargs):
        super(IsolatedTestRunner, self).setup_test_environment(*args, **kwargs)
        # gargoyle caches settings. Setting timeout to 0 prevents this,
        # increasing test isolation.
        gargoyle.timeout = 0


class DiscoveryCITestSuiteRunner(CITestSuiteRunner, IsolatedTestRunner):
    """Discovery based test runner for running with django-jenkins."""
    def build_suite(self, test_labels, extra_tests=None, **kwargs):
        suite = DiscoverRunner.build_suite(
            self, test_labels, extra_tests=extra_tests, **kwargs)
        signals.build_suite.send(sender=self, suite=suite)
        return reorder_suite(suite, (TestCase,))
