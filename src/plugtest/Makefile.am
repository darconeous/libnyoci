@CODE_COVERAGE_RULES@

AM_LIBS = $(CODE_COVERAGE_LDFLAGS)
AM_CFLAGS = $(CFLAGS) $(CODE_COVERAGE_CFLAGS)
AM_CPPFLAGS = $(CPPFLAGS) $(NYOCI_CPPFLAGS) $(MISSING_CPPFLAGS)

bin_PROGRAMS = nyoci-plugtest-server nyoci-plugtest-client
TESTS = selftest.sh

nyoci_plugtest_server_SOURCES = main-server.c plugtest-server.c plugtest-server.h
nyoci_plugtest_server_LDADD = ../libnyoci/libnyoci.la ../libnyociextra/libnyociextra.la

nyoci_plugtest_client_SOURCES = main-client.c
nyoci_plugtest_client_LDADD = ../libnyoci/libnyoci.la


TESTS_ENVIRONMENT = builddir='$(builddir)'

EXTRA_DIST = selftest.sh README.md
DISTCLEANFILES = .deps Makefile
