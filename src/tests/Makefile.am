AM_CPPFLAGS = $(CPPFLAGS) $(NYOCI_CPPFLAGS)

check_PROGRAMS =

@CODE_COVERAGE_RULES@

AM_LIBS = $(CODE_COVERAGE_LDFLAGS)
AM_CFLAGS = $(CODE_COVERAGE_CFLAGS)

check_PROGRAMS += test-concurrency
test_concurrency_SOURCES = test-concurrency.c
test_concurrency_LDADD = ../libnyoci/libnyoci.la

TESTS = test-concurrency

DISTCLEANFILES = .deps Makefile
