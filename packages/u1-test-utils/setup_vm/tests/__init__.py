import os
import shutil
import tempfile

from bzrlib import osutils

def override_env_var(name, value):
    """Modify the environment, setting or removing the env_variable.

    :param name: The environment variable to set.

    :param value: The value to set the environment to. If None, then
        the variable will be removed.

    :return: The original value of the environment variable.
    """
    orig = os.environ.get(name)
    if value is None:
        if orig is not None:
            del os.environ[name]
    else:
        # FIXME: supporting unicode values requires a way to acquire the
        # user encoding, punting for now -- vila 2013-01-30
        os.environ[name] = value
    return orig


def override_env(test, name, new):
    """Set an environment variable, and reset it after the test.

    :param name: The environment variable name.

    :param new: The value to set the variable to. If None, the 
        variable is deleted from the environment.

    :returns: The actual variable value.
    """
    value = override_env_var(name, new)
    test.addCleanup(override_env_var, name, value)
    return value


isolated_environ = {
    'HOME': None,
}


def isolate_env(test, env=None):
    """Isolate test from the environment variables.

    This is usually called in setUp for tests that needs to modify the
    environment variables and restore them after the test is run.

    :param test: A test instance

    :param env: A dict containing variable definitions to be installed. Only
        the variables present there are protected. They are initialized with
        the provided values.
    """
    if env is None:
        env = isolated_environ
    for name, value in env.items():
        override_env(test, name, value)


def set_cwd_to_tmp(test):
    """Create a temp dir an cd into it for the test duration.

    This is generally called during a test setup.
    """
    test.test_base_dir = tempfile.mkdtemp(prefix='mytests-', suffix='.tmp')
    test.addCleanup(shutil.rmtree, test.test_base_dir, True)
    current_dir = os.getcwdu()
    test.addCleanup(os.chdir, current_dir)
    os.chdir(test.test_base_dir)
