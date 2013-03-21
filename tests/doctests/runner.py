# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

import sys
import os
import unittest
import doctest
import logging

from zope.testbrowser.browser import Browser

from doctests.utils import (
    extract_text,
    find_tag_by_id,
    find_tags_by_class,
    find_tags_by_tag_name,
    find_main_content,
    hrefs,
    get_feedback_messages,
)
from openid.consumer.discover import OPENID_2_0_TYPE
from openid import oidutil

sys.path.append(os.path.abspath('../'))
# Set up Django settings
os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'
# setup needs to be imported *after* modifying sys.path
from setup import setUp

# Turn off logging
logging.disable(logging.CRITICAL)


def myLoggingFunction(message, level=None):
    pass
oidutil.log = myLoggingFunction


def fakeimport(modulename, module):
    parts = modulename.split('.')
    name = None
    for part in parts:
        if name is None:
            name = part
        else:
            name += '.' + part
        sys.modules[name] = module
    sys.modules[modulename] = module

import openidhelpers
fakeimport('canonical.signon.testing.openidhelpers', openidhelpers)


def setupBrowser(auth=None):
    """
    Taken from canonical.launchpad.testing.pages:
    Create a testbrowser object for use in pagetests.

    :param auth: HTTP authentication string. None for the anonymous user, or a
        string of the form 'Basic email:password' for an authenticated user.
    :return: A `Browser` object.
    """
    browser = Browser()
    # Set up our Browser objects with handleErrors set to False, since
    # that gives a tracebacks instead of unhelpful error messages.
    browser.handleErrors = False
    if auth is not None:
        browser.addHeader("Authorization", auth)
    return browser

flags = (doctest.ELLIPSIS | doctest.REPORT_NDIFF |
         doctest.REPORT_ONLY_FIRST_FAILURE)


def files(dirname):
    """ Finds all files below directory 'dirname' """
    if not os.path.exists(dirname):
        return []
    if not os.path.isdir(dirname):
        return [dirname]
    result = []
    filelist = os.listdir(dirname)
    for f in filelist:
        if f.startswith('_'):
            continue
        fullname = os.path.join(dirname, f)
        if os.path.isdir(fullname):
            result += files(fullname)
        else:
            result.append(fullname)
    return result

if __name__ == '__main__':
    suite = unittest.TestSuite()

    import optparse

    parser = optparse.OptionParser()
    parser.add_option("-m", "--mock", action="store_true",
        help="Run against the mock provider", dest="mock")
    options, args = parser.parse_args()

    if len(args) == 0:
        testfile = 'stories'
    else:
        testfile = args[-1]
    for f in files(testfile):
        globs = {'anon_browser': Browser(),
                 'browser': Browser(),
                 'user_browser': Browser(),
                 'setupBrowser': setupBrowser,
                 'extract_text': extract_text,
                 'find_tag_by_id': find_tag_by_id,
                 'find_tags_by_class': find_tags_by_class,
                 'find_tags_by_tag_name': find_tags_by_tag_name,
                 'find_main_content': find_main_content,
                 'hrefs': hrefs,
                 'get_feedback_messages': get_feedback_messages,
                 'real_webservice': not options.mock,
                 'PROTOCOL_URI': OPENID_2_0_TYPE,
                }
        suite.addTest(doctest.DocFileSuite(f, globs=globs,
            setUp=setUp, optionflags=flags))
    runner = unittest.TextTestRunner()
    runner.run(suite)
