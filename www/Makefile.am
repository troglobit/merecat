wwwdir         = $(WEBDIR)
SUBDIRS        = cgi-bin icons img
dist_www_DATA  = index.html main.css
dist_www_DATA += htpasswd.1.html merecat.conf.5.html merecat.8.html ssi.8.html

# Distributed for testing from the source tree, but not installed.
# phpinfo() dumps the full PHP configuration to anyone who asks.
EXTRA_DIST     = phpinfo.php test.php

man:
	../man.sh
