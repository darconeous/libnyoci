
AUTOMAKE_OPTIONS = subdir-objects
DISTCLEANFILES = .deps Makefile
AM_CPPFLAGS = $(CPPFLAGS) $(NYOCI_CPPFLAGS)

@CODE_COVERAGE_RULES@

noinst_LTLIBRARIES = libnyoci-plat-net.la

libnyoci_plat_net_la_CFLAGS = $(AM_CFLAGS) $(CODE_COVERAGE_CFLAGS) $(HIDDEN_VISIBILITY_CFLAGS)
libnyoci_plat_net_la_LDFLAGS = $(AM_LDFLAGS) $(CODE_COVERAGE_LDFLAGS)

libnyoci_plat_net_la_SOURCES = \
	nyoci-plat-net-internal.h \
	nyoci-plat-net.c \
	nyoci-plat-net.h \
	$(NULL)

pkginclude_HEADERS = \
	nyoci-plat-net.h \
	nyoci-plat-net-internal.h \
	$(NULL)
