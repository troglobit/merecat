#!/bin/sh -e
srvfiles="main.css index.html img/merecat.jpg"

mkdir -p srv/img

for file in $srvfiles; do
    cp ${srcdir}/../www/$file srv/$file
    gzip -c srv/$file   > srv/$file.gz
done

echo "Starting merecat httpd, config file ${srcdir}/merecat.conf"
../src/merecat -f ${srcdir}/merecat.conf -n -l debug srv &
echo $! >merecat.pid

sleep 2
