#!/bin/sh
#
# merecat.sh - startup script for merecat on FreeBSD
#
# This goes in /usr/local/etc/rc.d and gets run at boot-time.

case "$1" in

    start)
    if [ -x /usr/local/sbin/merecat_wrapper ] ; then
	echo -n " merecat"
	/usr/local/sbin/merecat_wrapper &
    fi
    ;;

    stop)
    kill -USR1 `cat /var/run/merecat.pid`
    ;;

    *)
    echo "usage: $0 { start | stop }" >&2
    exit 1
    ;;

esac
