@CODE_COVERAGE_RULES@

AM_LIBS = $(CODE_COVERAGE_LDFLAGS)
AM_CFLAGS = $(CODE_COVERAGE_CFLAGS)
AM_CPPFLAGS = $(CPPFLAGS) $(NYOCI_CPPFLAGS)

bin_PROGRAMS = nyocictl

nyocictl_SOURCES = main.c cmd_list.c cmd_get.c cmd_post.c help.c cmd_repeat.c cmd_delete.c
nyocictl_SOURCES += cmd_delete.h cmd_get.h cmd_list.h cmd_post.h cmd_repeat.h help.h nyocictl.h
nyocictl_LDADD = ../libnyoci/libnyoci.la $(MISSING_LIBADD)
nyocictl_CPPFLAGS = $(AM_CPPFLAGS) $(OPENSSL_INCLUDES) $(MISSING_CPPFLAGS)

DISTCLEANFILES = .deps Makefile
