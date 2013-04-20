#!/usr/bin/env python

import sys

import testtools.run
import unittest


class TestProgram(testtools.run.TestProgram):

    def __init__(self, module, argv, stdout=None, testRunner=None, exit=True):
        if testRunner is None:
            testRunner = unittest.TextTestRunner
        super(TestProgram, self).__init__(module, argv=argv, stdout=stdout,
                                          testRunner=testRunner, exit=exit)


# We discover tests under './tests', the python 'load_test' protocol can be
# used in test modules for more fancy stuff.
discover_args = ['discover',
                 '--start-directory', './tests',
                 '--top-level-directory', '.',
                 ]
TestProgram(__name__, argv=[sys.argv[0]] + discover_args + sys.argv[1:])
