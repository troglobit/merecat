if ENABLE_HTPASSWD
dist_man1_MANS = htpasswd.1
endif
dist_man8_MANS = redirect.8 ssi.8 merecat.8
# in.httpd.8 
SYMLINK        = httpd.8

# Hook in install merecat.8 --> in.httpd-8, httpd-8 symlinks
if CREATE_SYMLINKS
install-data-hook:
	@for file in $(SYMLINK); do					\
		link=$(DESTDIR)$(mandir)/man8/$$file;			\
		[ "`readlink $$link`" = "merecat.8" ] && continue;	\
		$(LN_S) merecat.8 $$link;				\
	done
endif
