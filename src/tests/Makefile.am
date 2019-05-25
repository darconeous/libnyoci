AM_CPPFLAGS = $(CPPFLAGS) $(NYOCI_CPPFLAGS)

check_PROGRAMS =

@CODE_COVERAGE_RULES@

AM_LIBS = $(CODE_COVERAGE_LDFLAGS)
AM_CFLAGS = $(CODE_COVERAGE_CFLAGS)

check_PROGRAMS += test-concurrency
test_concurrency_SOURCES = test-concurrency.c
test_concurrency_LDADD = ../libnyoci/libnyoci.la

check_PROGRAMS += test-issue-21
test_issue_21_SOURCES = test-issue-21.c
test_issue_21_LDADD = ../libnyoci/libnyoci.la ../libnyociextra/libnyociextra.la

TESTS = test-concurrency test-issue-21

DISTCLEANFILES = .deps Makefile
