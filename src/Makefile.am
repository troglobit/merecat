sbin_PROGRAMS       = merecat
SYMLINK             = in.httpd
merecat_SOURCES     = thttpd.c		thttpd.h	\
		      fdwatch.c		fdwatch.h	\
		      libhttpd.c	libhttpd.h	\
		      mmc.c 		mmc.h		\
		      timers.c		timers.h	\
		      tdate_parse.c	tdate_parse.h	\
		      mime_encodings.h mime_types.h version.h
merecat_CFLAGS      = -W -Wall -Wextra -Wno-unused-result -Wno-unused-parameter
merecat_CPPFLAGS    = -D_POSIX_SOURCE -D_BSD_SOURCE
merecat_LDADD       = libmatch.a

noinst_LIBRARIES    = libmatch.a
libmatch_a_SOURCES  = match.c match.h

# Hook in install merecat --> in.httpd symlink
install-exec-hook:
	@for file in $(SYMLINK); do						\
		link=$(DESTDIR)$(sbindir)/$$file;				\
		test `readlink $$link` = "$(sbin_PROGRAMS)" && continue;	\
		$(LN_S) $(sbin_PROGRAMS) $$link;				\
	done

uninstall-hook:
	@for file in $(SYMLINK); do				\
		$(RM) $(DESTDIR)$(sbindir)/$$file;		\
	done


