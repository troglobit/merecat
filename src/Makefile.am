AUTOMAKE_OPTIONS    = subdir-objects

sbin_PROGRAMS       = merecat
if ENABLE_HTPASSWD
sbin_PROGRAMS      += htpasswd
endif

# in.httpd
SYMLINK             = httpd
merecat_CFLAGS      = -fPIC -W -Wall -Wextra -std=gnu99
merecat_CFLAGS     += -Wno-unused-result -Wno-unused-parameter -Wno-unused-variable
merecat_CFLAGS     += $(zlib_CFLAGS)
merecat_CPPFLAGS    = -D_POSIX_SOURCE -D_BSD_SOURCE -D_GNU_SOURCE -D_DEFAULT_SOURCE
merecat_CPPFLAGS   += -DCONFDIR='"$(sysconfdir)"' -DLOCALSTATEDIR='"$(localstatedir)"'
merecat_CPPFLAGS   += -DRUNDIR='"$(runstatedir)"'
merecat_LDADD       = libmatch.a $(zlib_LIBS)
merecat_LDADD      += $(LIBS) $(LIBOBJS)
merecat_SOURCES     = base64.c		base64.h	\
		      fdwatch.c		fdwatch.h	\
		      file.c		file.h		\
		      libhttpd.c	libhttpd.h	\
		      md5.c 		md5.h		\
		      merecat.c		merecat.h	\
		      mmc.c 		mmc.h		\
		      pidfile.c		stack.c		\
		      srv.c		srv.h		\
		      timers.c		timers.h	\
		      tdate_parse.c	tdate_parse.h	\
		      mime_encodings.h	mime_types.h
if ENABLE_SSL
merecat_SOURCES    += ssl.c ssl.h
merecat_CFLAGS     += $(OpenSSL_CFLAGS)
merecat_LDADD      += $(OpenSSL_LIBS)
endif

if HAVE_CONFUSE
merecat_SOURCES    += conf.c conf.h
merecat_CFLAGS     += $(confuse_CFLAGS)
merecat_LDADD      += $(confuse_LIBS)
endif

if ENABLE_HTPASSWD
htpasswd_CFLAGS      = -W -Wall -Wextra -Wno-unused-result -Wno-unused-parameter
htpasswd_CPPFLAGS   = -DWEBDIR='"$(WEBDIR)"'
htpasswd_SOURCES    = htpasswd.c
endif

noinst_LIBRARIES    = libmatch.a
libmatch_a_SOURCES  = match.c match.h

# Hook in install merecat --> in.httpd, httpd symlinks
if CREATE_SYMLINKS
install-exec-hook:
	@for file in $(SYMLINK); do					\
		link=$(DESTDIR)$(sbindir)/$$file;			\
		[ "`readlink $$link`" = "merecat" ] && continue;	\
		$(LN_S) merecat $$link;					\
	done

uninstall-hook:
	@for file in $(SYMLINK); do					\
		$(RM) $(DESTDIR)$(sbindir)/$$file;			\
	done
endif
