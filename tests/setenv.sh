#!/bin/sh
set -ex

curl http://localhost:8086/cgi-bin/printenv 2>/dev/null |grep 'MERECAT_TEST_VAR=hello_setenv'
