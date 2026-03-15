#!/bin/sh

kill `cat merecat.pid`
sleep 1
rm -rf srv
rm -f cgi-bin merecat.pid
