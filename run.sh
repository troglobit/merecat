#!/bin/sh
# Serve volume /srv/ftp with merecat httpd on host port 80
docker run -dit --restart unless-stopped -h `hostname` \
       -v /srv/ftp:/var/www -p 80:80 troglobit/merecat:latest merecat -n /var/www

