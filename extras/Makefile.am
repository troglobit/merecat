AM_CPPFLAGS       = -DWEBDIR='"$(WEBDIR)"'
AM_CFLAGS         = -W -Wall -Wextra -Wno-unused-result -Wno-unused-parameter

sbin_PROGRAMS     = makeweb htpasswd
makeweb_SOURCES   = makeweb.c
htpasswd_SOURCES  = htpasswd.c

dist_sbin_SCRIPTS = syslogtocern

install-exec-hook:
	chgrp $(WEBGROUP) $(DESTDIR)$(sbindir)/makeweb
	chmod 2751 $(DESTDIR)$(sbindir)/makeweb
