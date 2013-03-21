#!/bin/bash

DEPS_PACKAGE=canonical-identity-provider-web-dependencies
REQUIRED_VERSION=12.01.20~0.IS.10.04

if test `dpkg -l $DEPS_PACKAGE 2> /dev/null |grep ^ii|wc -l` -eq 1; then
    INSTALLED_VERSION=`dpkg-query -W -f '${Version}\n' $DEPS_PACKAGE`
    if test $REQUIRED_VERSION = $INSTALLED_VERSION; then
      echo "Version of $DEPS_PACKAGE is OK"
    else
        echo "Incorrect version of $DEPS_PACKAGE is installed."
        echo "Required version is $REQUIRED_VERSION"
        echo "Installed version is $INSTALLED_VERSION"
        exit 1
    fi
else
    echo "$DEPS_PACKAGE not installed."
    exit 1
fi
