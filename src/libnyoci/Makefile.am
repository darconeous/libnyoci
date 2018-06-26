
AUTOMAKE_OPTIONS = subdir-objects
@CODE_COVERAGE_RULES@

lib_LTLIBRARIES = libnyoci.la

AM_LIBS = $(CODE_COVERAGE_LDFLAGS)
AM_CFLAGS = $(CFLAGS) $(CODE_COVERAGE_CFLAGS)
AM_CPPFLAGS = $(CPPFLAGS) $(NYOCI_CPPFLAGS)

pkgconfigdir = ${prefix}/lib/pkgconfig
pkgconfig_DATA = libnyoci.pc

libnyoci_la_SOURCES = \
	nyoci.c \
	nyoci-timer.c \
	coap.c coap.h \
	nyoci-outbound.c \
	nyoci-inbound.c \
	nyoci-observable.c \
	nyoci-transaction.c \
	nyoci-dupe.c \
	nyoci-missing.c \
	nyoci-session.c \
	nyoci-async.c \
	$(NULL)

libnyoci_la_SOURCES += \
	nyoci-helpers.h \
	nyoci-internal.h \
	nyoci-logging.h \
	nyoci-dupe.h \
	nyoci-missing.h \
	nyoci-async.h \
	nyoci-defaults.h \
	nyoci-status.h \
	$(NULL)

libnyoci_la_SOURCES += \
	btree.c btree.h \
	ll.h \
	url-helpers.c \
	fasthash.c \
	string-utils.c \
	url-helpers.h \
	fasthash.h \
	string-utils.h \
	assert-macros.h \
	$(NULL)

pkginclude_HEADERS = \
	libnyoci.h \
	nyoci-opts.h \
	nyoci-defaults.h \
	nyoci-timer.h \
	nyoci-transaction.h \
	nyoci-observable.h \
	nyoci-helpers.h \
	nyoci-session.h \
	nyoci-status.h \
	nyoci-async.h \
	nyoci-plat-net-func.h \
	nyoci-plat-tls-func.h \
	$(top_builddir)/src/libnyoci/nyoci-config.h \
	btree.h \
	coap.h \
	ll.h \
	$(NULL)

# Eventually these headers should be removed or reconsidered,
# but at the moment is is rather convenient to keep them around.
pkginclude_HEADERS += \
	assert-macros.h \
	fasthash.h \
	url-helpers.h \
	string-utils.h \
	nyoci-internal.h \
	nyoci-dupe.h \
	nyoci-logging.h \
	$(NULL)

EXTRA_DIST = nyoci-config.h.in

libnyoci_la_CFLAGS = $(AM_CFLAGS) $(PTHREAD_CFLAGS) $(HIDDEN_VISIBILITY_CFLAGS)
libnyoci_la_LIBADD = $(ALLOCA) $(PTHREAD_LIBS) ../plat-net/${NYOCI_PLAT_NET}/libnyoci-plat-net.la $(MISSING_LIBADD)
libnyoci_la_CPPFLAGS = $(AM_CPPFLAGS) $(OPENSSL_INCLUDES) $(MISSING_CPPFLAGS)
libnyoci_la_LDFLAGS = $(AM_LDFLAGS) $(OPENSSL_LDFLAGS)

if NYOCI_PLAT_TLS
#libnyoci_la_LIBADD += $(OPENSSL_LIBS)
libnyoci_la_LIBADD += ../plat-tls/${NYOCI_PLAT_TLS}/libnyoci-plat-tls.la
endif

check_PROGRAMS = btreetest
btreetest_SOURCES = btree.c
btreetest_CFLAGS = $(AM_CFLAGS) -DBTREE_SELF_TEST=1

DISTCLEANFILES = .deps Makefile

TESTS = btreetest
