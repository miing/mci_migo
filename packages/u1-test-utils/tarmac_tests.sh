#!/bin/sh
# How the tests are run in Jenkins by Tarmac

set -e

echo 'Setting up the virtual environment.'
fab bootstrap

echo "Running u1-test-utils tests in tarmac"
fab test
