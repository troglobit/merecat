cgidir            = $(WEBDIR)/cgi-bin
cgi_PROGRAMS      = redirect ssi
cgi_SCRIPTS       = printenv

redirect_SOURCES  = redirect.c
redirect_CPPFLAGS = -I$(top_srcdir)/src

ssi_SOURCES       = ssi.c
ssi_CPPFLAGS      = -I$(top_srcdir)/src
ssi_LDADD         = ../../src/libmatch.a
