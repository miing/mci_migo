#!/bin/bash

# find a valid and unused port to listen on
PORT=0
while [ $PORT -le 1024 ]; do
  PORT=$RANDOM
  # is the port in use?
  used=`netstat -lnt | grep ":$PORT" | grep -v grep | wc -l`
  if [ $used = 1 ]; then
    # port in use, skip it
    PORT=0
  fi
done
export PORT

# start clean
fab resetdb
fab manage:loaddata,test
fab manage:create_test_team
# get gargoyle flags from their use in the code
SST_FLAGS="allow_unverified;can_view_support_phone;captcha;login_by_phone;login_by_token;optional_captcha;paper_device;preflight;saml2;twofactor"
# fabric want ',' below and no trailing ',' either :-/
GARGOYLE_FLAGS=${SST_FLAGS//;/,}
fab gargoyle_flags:${GARGOYLE_FLAGS%,}

# launch sso server in background
screen -dmS sso fab run:0.0.0.0:$PORT

# launch local test server in background
screen -dmS emailserver .env/bin/python -c 'import localmail; localmail.run()'
sleep 10 # Time for the sso to start

# run tests
SST_BASE_URL="http://0.0.0.0:$PORT" fab acceptance:screenshot=true,report=xml,extended=true,flags="$SST_FLAGS"

# terminate sso server
screen -X -S sso quit

# terminate emailserver server
screen -X -S emailserver quit
