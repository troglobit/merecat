AUTOMAKE_OPTIONS    = subdir-objects no-dependencies

cgidir              = $(WEBDIR)/cgi-bin
cgi_PROGRAMS        = ssi
dist_cgi_SCRIPTS    = printenv onboard.py

ssi_SOURCES         = ssi.c
ssi_CPPFLAGS        = -I$(top_srcdir)/src
ssi_LDADD           = ../../src/libmatch.a $(LIBOBJS)
