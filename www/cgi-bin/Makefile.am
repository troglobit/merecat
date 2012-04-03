cgidir = $(WEBDIR)/cgi-bin

cgi_PROGRAMS = redirect ssi phf

redirect_SOURCES = redirect.c
redirect_CPPFLAGS = -I$(top_srcdir)/src

ssi_SOURCES = ssi.c
ssi_CPPFLAGS = -I$(top_srcdir)/src
ssi_LDADD = ../../src/libmatch.a

phf_SOURCES = phf.c
phf_CPPFLAGS = -I$(top_srcdir)/src

dist_cgi_DATA = printenv
