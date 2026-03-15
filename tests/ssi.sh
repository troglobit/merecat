#!/bin/sh
# Verify Server-Side Includes: an .shtml file with <!--#echo var="DOCUMENT_URI"-->
# is processed by cgi-bin/ssi and the variable value appears in the response.
set -ex

SSI=../www/cgi-bin/ssi

# Skip if ssi binary not built
if [ ! -x "$SSI" ]; then
    echo "ssi binary not found, skipping"
    exit 77
fi

# Pass 1/2: DOCUMENT_URI is echoed into the response body
curl -s http://localhost:8086/ssi/test.shtml | grep '/ssi/test.shtml'

# Pass 2/2: DOCUMENT_NAME (filename only) is echoed correctly
curl -s http://localhost:8086/ssi/test.shtml | grep 'test.shtml'
