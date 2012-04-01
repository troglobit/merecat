sbin_PROGRAMS = thttpd
thttpd_SOURCES = thttpd.c thttpd.h \
	fdwatch.c fdwatch.h \
	libhttpd.c libhttpd.h \
	mmc.c mmc.h \
	timers.c timers.h \
	tdate_parse.c tdate_parse.h \
	mime_encodings.h mime_types.h version.h
thttpd_LDADD = libmatch.a

noinst_LIBRARIES = libmatch.a
libmatch_a_SOURCES = match.c match.h
