AM_CPPFLAGS = -DWEBDIR='"$(WEBDIR)"'

sbin_PROGRAMS = makeweb htpasswd
makeweb_SOURCES = makeweb.c
htpasswd_SOURCES = htpasswd.c

dist_sbin_SCRIPTS = syslogtocern

install-exec-hook:
	chgrp $(WEBGROUP) $(sbindir)/makeweb
	chmod 2751 $(sbindir)/makeweb
