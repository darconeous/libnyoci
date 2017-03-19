AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src doc

DISTCLEANFILES = config.log config.status Makefile libtool make.out

EXTRA_DIST = bootstrap.sh README.md NEWS.md CHANGELOG LICENSE etc/Dockerfile etc/build-in-docker.sh etc/run-in-docker.sh CONTRIBUTING.md .default-version

# Metafiles
EXTRA_DIST += .gitignore .uncrustify.cfg .travis.yml

# Make sure the contiki bits make it into the archive.
EXTRA_DIST += contiki-src/examples/nyoci-simple/.gitignore contiki-src/examples/nyoci-simple/Makefile contiki-src/examples/nyoci-simple/nyoci-simple.c
EXTRA_DIST += contiki-src/examples/nyoci-plugtest/.gitignore contiki-src/examples/nyoci-plugtest/Makefile contiki-src/examples/nyoci-plugtest/nyoci-plugtest.c
EXTRA_DIST += contiki-src/examples/nyoci-complex/.gitignore contiki-src/examples/nyoci-complex/Makefile contiki-src/examples/nyoci-complex/nyoci-complex.c
EXTRA_DIST += contiki-src/led-node.c contiki-src/led-node.h contiki-src/Makefile.nyoci contiki-src/sensor-node.c contiki-src/sensor-node.h contiki-src/nyoci-task.c contiki-src/nyoci-task.h contiki-src/nyoci-contiki-config.h


HASH_VERSION = $(shell                                                   \
	git describe --dirty --match __poison__ --always 2> /dev/null        \
)

EXTRA_VERSION = $(shell                                                  \
	git describe --all --contains 016765d4b7f23d25d97ba2670ee00cba13934ba8 1> /dev/null 2> /dev/null \
		&& (test "`git describe 2> /dev/null | sed 's:^full/::'`" = $(VERSION) || echo -g$(HASH_VERSION))  \
)

distdir = $(PACKAGE)-$(VERSION)$(EXTRA_VERSION)

@CODE_COVERAGE_RULES@
