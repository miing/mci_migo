#!/bin/sh

set -e

DOWNLOAD_CACHE=$(dirname `dirname $PWD`)/isd-download-cache
if [ -d $DOWNLOAD_CACHE ]; then
    echo "Updating download cache at dir" $DOWNLOAD_CACHE
    bzr pull -d $DOWNLOAD_CACHE
else
    echo "Branching the download cache in dir" $DOWNLOAD_CACHE
    bzr branch lp:~canonical-isd-hackers/+junk/download-cache $DOWNLOAD_CACHE
fi
fab bootstrap:download_cache_path=$DOWNLOAD_CACHE
