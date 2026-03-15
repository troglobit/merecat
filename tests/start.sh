#!/bin/sh -e
srvfiles="main.css index.html img/merecat.jpg"
if [ -z "$srcdir" ]; then
    srcdir=.
fi

mkdir -p srv/img srv/cgi-bin srv/gallery srv/withindex srv/ssi

for file in $srvfiles; do
    cp ${srcdir}/../www/$file srv/$file
    gzip -c srv/$file   > srv/$file.gz
done
cp ${srcdir}/../www/cgi-bin/printenv srv/cgi-bin/
if [ -x ${srcdir}/../www/cgi-bin/ssi ]; then
    cp ${srcdir}/../www/cgi-bin/ssi srv/cgi-bin/
fi

# dirlisting: gallery has no index, withindex has one
echo 'file1' > srv/gallery/file1.txt
echo 'file2' > srv/gallery/file2.txt
echo '<html>withindex-index</html>' > srv/withindex/index.html

# ssi: minimal .shtml that echoes its own URI and filename
cat > srv/ssi/test.shtml <<'SHTML'
<!--#echo var="DOCUMENT_URI" -->
<!--#echo var="DOCUMENT_NAME" -->
SHTML

# Symlink cgi-bin into the test working directory so merecat's pre-chdir
# access() check for ssi cgi-path = "cgi-bin/ssi" succeeds.
ln -sf srv/cgi-bin cgi-bin

echo "Starting merecat httpd, config file ${srcdir}/merecat.conf"
../src/merecat -f ${srcdir}/merecat.conf -n -l debug srv &
echo $! >merecat.pid

sleep 2
