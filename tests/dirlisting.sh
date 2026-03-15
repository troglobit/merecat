#!/bin/sh
# Verify directory listing: a directory with no index file gets an auto-generated
# HTML table, while a directory with an index file serves that file instead.
set -ex

# Pass 1/2: directory with no index file -> listing with <table>
curl -s http://localhost:8086/gallery/ | grep -i '<table'

# Pass 2/2: directory with index.html -> index served, no listing
curl -s http://localhost:8086/withindex/ | grep 'withindex-index'
