#!/bin/sh

kill `cat merecat.pid`
sleep 1
rm -rf srv
rm merecat.pid
