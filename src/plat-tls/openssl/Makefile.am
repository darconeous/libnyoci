
AUTOMAKE_OPTIONS = subdir-objects
DISTCLEANFILES = .deps Makefile

@CODE_COVERAGE_RULES@

noinst_LTLIBRARIES = libnyoci-plat-tls.la

libnyoci_plat_tls_la_CFLAGS = $(AM_CFLAGS) $(CODE_COVERAGE_CFLAGS) $(HIDDEN_VISIBILITY_CFLAGS)
libnyoci_plat_tls_la_CPPFLAGS = $(AM_CPPFLAGS) $(NYOCI_CPPFLAGS) $(OPENSSL_INCLUDES)
libnyoci_plat_tls_la_LDFLAGS = $(AM_LDFLAGS) $(CODE_COVERAGE_LDFLAGS)
libnyoci_plat_tls_la_LIBADD = $(AM_LIBADD) $(OPENSSL_LIBS)

libnyoci_plat_tls_la_SOURCES = \
	nyoci-plat-tls.c \
	nyoci-plat-tls.h \
	$(NULL)

pkginclude_HEADERS = \
	nyoci-plat-tls.h \
	$(NULL)
