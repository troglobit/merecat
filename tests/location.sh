#!/bin/sh
# Verify location directive
set -ex

# Fetch from 8080:/.secret/path
echo "Pass 1/2"
curl -s -I http://localhost:8080/.secret/path/merecat.jpg | tee foo |grep "200 OK"
cat foo; rm foo

# But not from :8086
echo "Pass 2/2"
curl -s -I http://localhost:8086/.secret/path/merecat.jpg |tee foo | grep "404 Not Found"
cat foo; rm foo
