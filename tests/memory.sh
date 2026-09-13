#!/bin/sh
# Verify the connection table is sized from max-connections and not from
# the file descriptor limit.  systemd grants services a high RLIMIT_NOFILE
# (524288 by default), and merecat raises its soft limit to the hard one,
# so sizing the table from it used to cost ~190 MiB of resident memory.
set -ex

# Needs /proc to read VmRSS
[ -r /proc/self/status ] || exit 77

WANT=262144

hard=$(ulimit -Hn)
if [ "$hard" != "unlimited" ] && [ "$hard" -lt "$WANT" ]; then
    echo "hard limit $hard is below $WANT, cannot test"
    exit 77
fi

cat >memory.conf <<CONF
port = 8097
CONF

( ulimit -n $WANT; exec ../src/merecat -f memory.conf -n -l err srv ) &
pid=$!
sleep 2

# The server must actually be serving, an early exit would also be "small"
curl -s -m 5 -o /dev/null http://localhost:8097/

rss=$(awk '/^VmRSS:/ {print $2}' /proc/$pid/status)
echo "VmRSS with ulimit -n $WANT: $rss kB"

kill $pid 2>/dev/null || true
wait $pid 2>/dev/null || true
rm -f memory.conf

# 1024 slots of ~344 B is well under 1 MiB, so anything near the old
# behaviour (~94 MiB at this descriptor limit) fails here.
test "$rss" -lt 40960
