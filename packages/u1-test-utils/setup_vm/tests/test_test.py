import os

import testtools

import tests


def assertTestSuccess(test, inner):
    """The received test runs successfully."""
    result = testtools.TestResult()
    inner.run(result)
    test.assertEqual(0, len(result.errors) + len(result.failures))
    test.assertEqual(1, result.testsRun)
    return result


class TestEnv(testtools.TestCase):


    def test_env_preserved(self):
        os.environ['NOBODY_USES_THIS'] = 'foo'

        class Inner(testtools.TestCase):

            def  test_overridden(self):
                tests.isolate_env(self, {'NOBODY_USES_THIS': 'bar'})
                self.assertEqual('bar', os.environ['NOBODY_USES_THIS'])

        assertTestSuccess(self, Inner('test_overridden'))
        self.assertEqual('foo', os.environ['NOBODY_USES_THIS'])

    def test_env_var_deleted(self):
        os.environ['NOBODY_USES_THIS'] = 'foo'

        class Inner(testtools.TestCase):

            def  test_deleted(self):
                tests.isolate_env(self, {'NOBODY_USES_THIS': None})
                self.assertIs('deleted',
                              os.environ.get('NOBODY_USES_THIS', 'deleted'))
        assertTestSuccess(self, Inner('test_deleted'))
        self.assertEqual('foo', os.environ['NOBODY_USES_THIS'])


class TestTmp(testtools.TestCase):

    def test_cwd_in_tmp(self):

        class Inner(testtools.TestCase):

            def setUp(self):
                super(Inner, self).setUp()
                tests.set_cwd_to_tmp(self)

            def test_cwd_in_tmp(self):
                self.assertEqual(os.getcwdu(), self.test_base_dir)

        assertTestSuccess(self, Inner('test_cwd_in_tmp'))
