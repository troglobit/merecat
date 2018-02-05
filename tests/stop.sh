#!/bin/sh

cd ../www
rm *.gz
if [ -e /tmp/merecat.files ]; then
    rm -f `cat /tmp/merecat.files`
    rm /tmp/merecat.files
fi

kill `cat /tmp/merecat.test`
rm /tmp/merecat.test
