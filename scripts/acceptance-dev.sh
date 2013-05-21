#!/bin/bash
set -ue

function usage {
  cat  << EOF
Usage: $0 [-t TESTCASE] [-h|-f] [-p PORT]
Run SSO acceptance tests on a random port.
  -t [TESTCASE]   run using TESTCASE regex. Will not reset db
  -h              run headless (ie, using headless=true)
  -f              run headful (ie, using headless=false)
  -p [PORT]       use a specific port (e.g. -p 8001)
  -c              force a clean db (if using -t option)
EOF
}

# random port by default
PORT=$(./scripts/random-port.sh)
TESTCASE=
HEADLESS=
CLEAN="false"

while getopts ":t:hfcp:" opt; do
  case $opt in
    t) TESTCASE=$OPTARG ;;
    h) HEADLESS="true" ;;
    f) HEADLESS="false" ;;
    p) PORT=$OPTARG ;;
    c) CLEAN="true" ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      usage
      exit 1
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      usage
      exit 1
      ;;
  esac
done

function clean_up {
    # terminate sso server
    screen -X -S sso quit
    # terminate emailserver server
    screen -X -S emailserver quit
    exit
}

export PORT=$PORT
export SSO_HOSTNAME="0.0.0.0:$PORT"
export SST_BASE_URL="http://$SSO_HOSTNAME"

# only reset db if we're doing a full run or explicitly told to
if [ -z $TESTCASE ] || $CLEAN
then
  echo "Resetting db"
  # start clean
  fab resetdb
  fab manage:loaddata,test
  fab manage:create_test_team
  # add openid RP config
  # we need this to explicitly allow unverified logins
  fab manage:add_openid_rp_config,$SST_BASE_URL/consumer,--allow-unverified,--allowed-user-attribs="fullname\,nickname\,email\,language,account_verified"
fi

echo -n "Finding SST flags..."
SST_FLAGS=$(fab --hide=running,status manage:switches,--short | tr '[:upper:]' '[:lower:]')
echo done
echo SST_FLAGS: $SST_FLAGS

# handle exit cleanly (mainly Ctrl-C)
trap clean_up SIGHUP SIGINT SIGTERM

echo -n Starting SSO in background on port $PORT...
screen -dmS sso fab run
echo done

echo -n Starting localmail test server in background...
screen -dmS emailserver .env/bin/python -c 'import localmail; localmail.run()'
echo done

echo -n "Waiting for SSO to start"
while [ $(netstat -lnt | grep ":$PORT" | grep -v grep | wc -l) != 1 ]
do
    echo -n .
    sleep 0.5
done
echo "done"

runcmd="fab acceptance:screenshot=true,report=xml,flags=$SST_FLAGS"

if [ -n "$HEADLESS" ]; then
  runcmd="$runcmd,headless=$HEADLESS"
fi
if [ -n "$TESTCASE" ]; then
  runcmd="$runcmd,testcase=\"$TESTCASE\""
fi
echo $runcmd
$runcmd

clean_up
