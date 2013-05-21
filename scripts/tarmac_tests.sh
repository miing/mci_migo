#!/bin/sh
# How the tests are run in Jenkins by Tarmac

set -e

./scripts/bootstrap-with-cache.sh

# Set up the database.
echo "Changing local.cfg to use the system database"
sed -i 's/db_host = .*/db_host =/g' django_project/local.cfg
fab resetdb

# run tests
echo "Running canonical-identity-provider tests in tarmac"
fab test && fab brand:ubuntuone test:extra=webui
