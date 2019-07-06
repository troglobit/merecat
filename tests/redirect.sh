#!/bin/sh
# https://en.wikipedia.org/wiki/URL_redirection

curl -Ls -w %{url_effective} http://127.0.0.1:8080 |grep http://127.0.0.1:8086/
