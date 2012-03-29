SUBDIRS = cgi-src extras

SOURCES = thttpd.c libhttpd.c fdwatch.c mmc.c timers.c match.c tdate_parse.c
HEADERS = config.h fdwatch.h libhttpd.h match.h mime_encodings.h mime_types.h mmc.h tdate_parse.h timers.h version.h

bin_PROGRAMS = thttpd
thttpd_SOURCES = $(SOURCES) $(HEADERS)

dist_man_MANS = thttpd.8

mime_encodings.h: mime_encodings.txt
	rm -f mime_encodings.h
	sed < mime_encodings.txt > mime_encodings.h \
	  -e 's/#.*//' -e 's/[ 	]*$$//' -e '/^$$/d' \
	  -e 's/[ 	][ 	]*/", 0, "/' -e 's/^/{ "/' -e 's/$$/", 0 },/'

mime_types.h: mime_types.txt
	rm -f mime_types.h
	sed < mime_types.txt > mime_types.h \
	  -e 's/#.*//' -e 's/[ 	]*$$//' -e '/^$$/d' \
	  -e 's/[ 	][ 	]*/", 0, "/' -e 's/^/{ "/' -e 's/$$/", 0 },/'
