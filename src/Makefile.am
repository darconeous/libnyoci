DIST_SUBDIRS = missing @PLATFORM_SUBDIRS@ libnyoci libnyociextra nyocictl plugtest examples tests

DISTCLEANFILES = .deps Makefile

EXTRA_DIST =

SUBDIRS = missing @NYOCI_PLAT_NET_DIR@

if NYOCI_PLAT_TLS
SUBDIRS += @NYOCI_PLAT_TLS_DIR@
endif

SUBDIRS += libnyoci

if BUILD_LIBNYOCIEXTRA
SUBDIRS += libnyociextra
endif

if BUILD_NYOCICTL
SUBDIRS += nyocictl
endif

if BUILD_PLUGTEST
SUBDIRS += plugtest
endif

if BUILD_EXAMPLES
SUBDIRS += examples
endif

SUBDIRS += tests

@CODE_COVERAGE_RULES@
AM_LIBS = $(CODE_COVERAGE_LDFLAGS)
AM_CFLAGS = $(CODE_COVERAGE_CFLAGS)

EXTRA_DIST += version.c.in version.h
CLEANFILES = $(top_builddir)/$(subdir)/version.c
SOURCE_VERSION=$(shell git describe --dirty --always --match "[0-9].*" 2> /dev/null)
BUILT_SOURCES  = $(top_builddir)/$(subdir)/version.c
.INTERMEDIATE: $(top_builddir)/$(subdir)/version.c
$(top_builddir)/$(subdir)/version.c: version.c.in Makefile
	sed 's/SOURCE_VERSION/"$(SOURCE_VERSION)"/' < $< > $@
