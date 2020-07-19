#!/bin/sh -e
srvfiles="main.css index.html img/merecat.jpg"
if [ -z "$srcdir" ]; then
    srcdir=.
fi

mkdir -p srv/img srv/cgi-bin

for file in $srvfiles; do
    cp ${srcdir}/../www/$file srv/$file
    gzip -c srv/$file   > srv/$file.gz
done
cp ${srcdir}/../www/cgi-bin/printenv srv/cgi-bin/

echo "Starting merecat httpd, config file ${srcdir}/merecat.conf"
../src/merecat -f ${srcdir}/merecat.conf -n -l debug srv &
echo $! >merecat.pid

sleep 2
