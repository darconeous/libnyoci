
AUTOMAKE_OPTIONS = subdir-objects
DISTCLEANFILES = .deps Makefile

lib_LTLIBRARIES = libnyociextra.la

@CODE_COVERAGE_RULES@

pkgconfigdir = ${prefix}/lib/pkgconfig
pkgconfig_DATA = libnyociextra.pc

AM_LIBS = $(CODE_COVERAGE_LDFLAGS)
AM_CFLAGS = $(CFLAGS) $(CODE_COVERAGE_CFLAGS) $(HIDDEN_VISIBILITY_CFLAGS)
AM_CPPFLAGS = $(CPPFLAGS) $(NYOCI_CPPFLAGS) $(MISSING_CPPFLAGS)

libnyociextra_la_SOURCES = \
	nyoci-node-router.c nyoci-node-router.h \
	nyoci-list.c \
	nyoci-var-handler.c nyoci-var-handler.h \
	$(NULL)

extraincludedir = $(includedir)/libnyociextra
extrainclude_HEADERS = \
	nyoci-node-router.h \
	nyoci-var-handler.h \
	libnyociextra.h \
	$(NULL)

libnyociextra_la_LIBADD = $(ALLOCA) $(PTHREAD_LIBS) ../libnyoci/libnyoci.la
