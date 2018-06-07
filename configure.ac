
AC_PREREQ(2.59)

AC_INIT([LibNyoci],m4_esyscmd([printf "%s" `cat .default-version`]),[https://github.com/darconeous/libnyoci/],[libnyoci],[http://libnyoci.org/])

AC_CONFIG_AUX_DIR([m4])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_LIBOBJ_DIR([src/missing/])
AC_CONFIG_SRCDIR([src/libnyoci/nyoci.c])
AC_CONFIG_HEADERS([src/config.h src/libnyoci/nyoci-config.h])

AM_INIT_AUTOMAKE

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
m4_ifdef([AX_CODE_COVERAGE], [AX_CODE_COVERAGE], [AC_SUBST([CODE_COVERAGE_RULES])])

AC_GNU_SOURCE
AC_PROG_LIBTOOL
AM_MAINTAINER_MODE
LT_INIT

dnl ###########################################################################

AC_PROG_CC

AX_PTHREAD

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_TIME
AC_CHECK_HEADERS([stdlib.h dlfcn.h unistd.h string.h stdio.h errno.h stdarg.h stddef.h stdint.h stdbool.h])
AC_CHECK_HEADERS([alloca.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_C_VOLATILE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_CHECK_FUNCS([alloca memcmp memset strtol strdup strndup strlcpy strlcat stpncpy vsnprintf vsprintf snprintf getloadavg])
AC_REPLACE_FUNCS([getline])

dnl ###########################################################################

AC_DEFUN([REPLACE_MISSING_FUNC], [
    AC_CHECK_FUNC($1, [], [
        nl_cv_missing_$1=yes
        MISSING_CPPFLAGS="${MISSING_CPPFLAGS} "'-include $(top_srcdir)/src/missing/$1/$1.h'
        MISSING_LIBADD="${MISSING_LIBADD} "'$(top_builddir)/src/missing/$1/lib$1.la'
    ])
    AM_CONDITIONAL(m4_toupper(MISSING_$1), [test "${nl_cv_missing_$1}" = "yes"])
])
AC_SUBST(MISSING_CPPFLAGS)
AC_SUBST(MISSING_LIBADD)

REPLACE_MISSING_FUNC([strlcpy])
REPLACE_MISSING_FUNC([strlcat])

dnl ###########################################################################

#-fvisibility=hidden and -fvisibility-inlines-hidden

AC_DEFUN([NY_CC_SUPPORTS_VISIBILITY], [
	AC_LANG_PUSH(C)
	prev_CFLAGS="${CFLAGS}"
	CFLAGS="-fvisibility=hidden"
	AC_MSG_CHECKING([for simple visibility declarations])
	AC_TRY_COMPILE(
			[extern __attribute__((__visibility__("hidden"))) int hiddenvar;
			 extern __attribute__((__visibility__("default"))) int exportedvar;
			 extern __attribute__((__visibility__("hidden"))) int hiddenfunc (void);
			 extern __attribute__((__visibility__("default"))) int exportedfunc (void);],
			[],
			[
				AC_MSG_RESULT([yes])
				$1
			], [
				AC_MSG_RESULT([no])
				$2
			])
	CFLAGS="${prev_CFLAGS}"
	unset prev_CFLAGS
	AC_LANG_POP(C)
])

NY_CC_SUPPORTS_VISIBILITY([
	AC_DEFINE_UNQUOTED([NYOCI_INTERNAL_EXTERN], [__attribute__((visibility("default"))) extern], [.])
	AC_DEFINE_UNQUOTED([NYOCI_API_EXTERN], [__attribute__((visibility("default"))) extern], [.])
	HIDDEN_VISIBILITY_CFLAGS="$CFLAGS"
])

AC_SUBST([HIDDEN_VISIBILITY_CFLAGS])

m4_ifdef([AX_GCC_FUNC_ATTRIBUTE], [
    AX_GCC_FUNC_ATTRIBUTE([deprecated])
    AX_GCC_FUNC_ATTRIBUTE([pure])
])

dnl ###########################################################################
dnl ## GIT VERSION INTEGRATION ################################################

SOURCE_VERSION=m4_esyscmd([
	configver="$PACKAGE_VERSION"
	(test -d .git && gitver=`git describe --dirty` && printf "$gitver") 2>/dev/null ||
	(test -d .git && gitver=`git describe --always` && printf "$configver-g$gitver") 2>/dev/null ||
	printf "$configver"
])

AC_DEFINE_UNQUOTED([SOURCE_VERSION], ["`eval echo "$SOURCE_VERSION"`"], [Source version])


dnl ###########################################################################
dnl ## PLATFORM WRAPPERS ######################################################

dnl This is the list of network platform wrappers included with
dnl LibNyoci. As platforms are added, they should be appended to
dnl this list.
m4_define(AVAILABLE_NET_PLATFORMS, [ dnl
    posix                            dnl
    uip                              dnl
dnl lwip
])

dnl This is the list of TLS wrappers included with LibNyoci. As
dnl others are added, they should be appended to this list.
m4_define(AVAILABLE_TLS_PLATFORMS, [ dnl
    openssl                          dnl
])

# Set up AC_CONFIG_FILES for all of the supported net platforms
AC_CONFIG_FILES(m4_normalize(m4_foreach_w(THIS_PLATFORM,AVAILABLE_NET_PLATFORMS,[src/plat-net/[]THIS_PLATFORM/Makefile ])))

# Set up AC_CONFIG_FILES for all of the supported TLS wrappers
AC_CONFIG_FILES(m4_normalize(m4_foreach_w(THIS_PLATFORM,AVAILABLE_TLS_PLATFORMS,[src/plat-tls/[]THIS_PLATFORM/Makefile ])))

PLATFORM_SUBDIRS="[]m4_foreach_w(THIS_PLATFORM,AVAILABLE_NET_PLATFORMS,plat-net/[]THIS_PLATFORM )dnl
                  []m4_foreach_w(THIS_PLATFORM,AVAILABLE_TLS_PLATFORMS,plat-tls/[]THIS_PLATFORM )"
AC_SUBST(PLATFORM_SUBDIRS)


dnl ###########################################################################
dnl ## NETWORK ADDRESS FAMILY SUPPORT #########################################

AC_ARG_WITH(address-family, AC_HELP_STRING([--with-address-family=[inet|inet6]],
            [Specify address family (inet6 is the default)]), [
    if test "${withval}" = "inet"
	then NYOCI_PLAT_NET_POSIX_FAMILY=AF_INET
	     NYOCI_PLAT_NET=posix
    elif test "${withval}" = "inet6"
	then NYOCI_PLAT_NET_POSIX_FAMILY=AF_INET6
	     NYOCI_PLAT_NET=posix
	else AC_MSG_ERROR(["Unknown family '${withval}'"])
    fi
])


dnl ###########################################################################
dnl ## NETWORK PLATFORM SUPPORT ###############################################

NYOCI_PLAT_NET=${NYOCI_PLAT_NET-posix}
NYOCI_PLAT_NET_DIR='plat-net/$(NYOCI_PLAT_NET)'
AC_DEFINE_UNQUOTED([NYOCI_PLAT_NET],[${NYOCI_PLAT_NET}],[LibNyoci network abstraction])
AC_SUBST([NYOCI_PLAT_NET])
AC_SUBST([NYOCI_PLAT_NET_DIR])
NYOCI_CPPFLAGS+=' -I$(top_builddir)/src -I$(top_srcdir)/src -I$(top_srcdir)/src/libnyoci -I$(top_srcdir)/src/plat-net/$(NYOCI_PLAT_NET)'


dnl ###########################################################################

AC_ARG_ENABLE(singleton, AC_HELP_STRING([--enable-singleton], [Make nyoci instance a singleton)]), [
    if test "${enable_singleton}" = "yes"
    then NYOCI_SINGLETON=1
    else NYOCI_SINGLETON=0
    fi
])


dnl ###########################################################################

AC_ARG_ENABLE(embedded, AC_HELP_STRING([--enable-embedded], [enable embedded mode]), [])

if test "${enable_embedded}" = "yes"
then
	NYOCI_EMBEDDED=1
	enable_nyocictl=${enable_nyocictl-no}
fi

AC_CHECK_FUNCS([malloc],[],[NYOCI_AVOID_MALLOC=${NYOCI_AVOID_MALLOC-1}])
AC_CHECK_FUNCS([printf fprintf sprintf vsnprintf],[],[NYOCI_AVOID_PRINTF=${NYOCI_AVOID_PRINTF-1}])


dnl ###########################################################################

AC_ARG_ENABLE(debug, AC_HELP_STRING([--enable-debug],
            [enable compiling with debugging information]), [
    if (test "${enableval}" = "yes" &&
                test "${ac_cv_prog_cc_g}" = "yes"); then
        CFLAGS="$CFLAGS -g -DDEBUG=1"
        CXXFLAGS="$CXXFLAGS -g -DDEBUG=1"
    fi
    if (test "${enableval}" = "verbose" &&
                test "${ac_cv_prog_cc_g}" = "yes"); then
        CFLAGS="$CFLAGS -g -DDEBUG=1 -DVERBOSE_DEBUG=1"
        CXXFLAGS="$CXXFLAGS -g -DDEBUG=1 -DVERBOSE_DEBUG=1"
    fi
])


dnl ###########################################################################

AC_ARG_ENABLE(examples, AC_HELP_STRING([--disable-examples], [Disable building examples]), [])
AM_CONDITIONAL([BUILD_EXAMPLES],test "${enable_examples}" != "no")


dnl ###########################################################################

AC_ARG_ENABLE(nyocictl, AC_HELP_STRING([--disable-nyocictl], [Disable building nyocictl]), [])

dnl Required Functions
if test "${enable_nyocictl}" != "no"
then
AC_CHECK_FUNCS([gettimeofday setenv strchr strdup strerror strndup strstr strtol printf fprintf], [], [
	if test "${enable_nyocictl}" == "yes"
	then AC_MSG_ERROR([Missing required functions for nyocictl])
	fi
	enable_nyocictl=${enable_nyocictl-no}
])
fi

AM_CONDITIONAL([BUILD_NYOCICTL],test "${enable_nyocictl}" != "no")

dnl ###########################################################################

AC_ARG_ENABLE(plugtest, AC_HELP_STRING([--disable-plugtest], [Disable building plugtest]), [])
AM_CONDITIONAL([BUILD_PLUGTEST],test "${enable_plugtest}" != "no")


dnl ###########################################################################
dnl ### LIBNYOCIEXTRA SUPPORT #################################################

AC_ARG_ENABLE(extra, AC_HELP_STRING([--disable-extra], [Disable building libnyociextra]), [])
AM_CONDITIONAL([BUILD_LIBNYOCIEXTRA],test "${enable_extra}" != "no")


dnl ###########################################################################
dnl ### TLS SUPPORT ###########################################################

unset NYOCI_PLAT_TLS

AC_ARG_ENABLE(tls, AC_HELP_STRING([--enable-tls], [Enable experimental TLS support]), [], [enable_tls=no])

if test "x${enable_tls}" != "xno"
then

if test "x${enable_tls-openssl}" == "xopenssl" -o "x${enable_tls}" == "xyes" -o "${with_openssl+set}" == "set"
then AX_CHECK_OPENSSL([
    NYOCI_PLAT_TLS=openssl

	AC_DEFINE_UNQUOTED([HAVE_OPENSSL],[1],[Set if OpenSSL is present])

	AC_CHECK_FUNC([HMAC_CTX_new],[AC_DEFINE_UNQUOTED([HAVE_OPENSSL_HMAC_CTX_NEW],[1],[Set if OpenSSL has HMAC_CTX_new()])])
	AC_CHECK_FUNC([DTLSv1_2_method],[AC_DEFINE_UNQUOTED([HAVE_OPENSSL_DTLSV1_2_METHOD],[1],[Set if OpenSSL has DTLSv1_2_method()])])
	AC_CHECK_FUNC([DTLSv1_method],[AC_DEFINE_UNQUOTED([HAVE_OPENSSL_DTLSV1_METHOD],[1],[Set if OpenSSL has DTLSv1_method()])])
	AC_CHECK_FUNC([DTLS_method],[AC_DEFINE_UNQUOTED([HAVE_OPENSSL_DTLS_METHOD],[1],[Set if OpenSSL has DTLS_method()])])
	AC_CHECK_FUNC([SSL_CONF_CTX_new],[AC_DEFINE_UNQUOTED([HAVE_OPENSSL_SSL_CONF_CTX_NEW],[1],[Set if OpenSSL has SSL_CONF_CTX_new()])])
	AC_CHECK_FUNC([SSL_CONF_finish],[AC_DEFINE_UNQUOTED([HAVE_OPENSSL_SSL_CONF_FINISH],[1],[Set if OpenSSL has SSL_CONF_finish()])])
],[
    if test "x${enable_tls-openssl}" == "xopenssl" -o "${with_openssl+set}" == "set"
    then AC_MSG_ERROR([Could not find usable OpenSSL])
    fi
])
fi
if test "x${enable_tls+set}" == "xset" -a "x${NYOCI_PLAT_TLS+set}" != "xset"
then AC_MSG_ERROR([TLS support explicitly requested but unable to find viable TLS implementation])
fi
fi

if test "${NYOCI_PLAT_TLS+set}" == "set"
then
    NYOCI_CPPFLAGS+=' -I$(top_srcdir)/src/plat-tls/$(NYOCI_PLAT_TLS)'
    AC_DEFINE_UNQUOTED([NYOCI_PLAT_TLS],[${NYOCI_PLAT_TLS}],[LibNyoci TLS abstraction])
fi

AM_CONDITIONAL([NYOCI_PLAT_TLS],test "${NYOCI_PLAT_TLS+set}" == "set")
AC_SUBST([NYOCI_PLAT_TLS])

NYOCI_PLAT_TLS_DIR='plat-tls/$(NYOCI_PLAT_TLS)'
AC_SUBST([NYOCI_PLAT_TLS_DIR])




dnl ###########################################################################

HAVE_LIBREADLINE=false
AC_ARG_ENABLE(libreadline,
    [  --disable-libreadline  Do not use libreadline],
	nyoci_check_for_libreadline="$enableval",
	nyoci_check_for_libreadline=yes
)
if test x"$nyoci_check_for_libreadline" = xyes; then :
	AC_CHECK_HEADER([readline/readline.h],AC_CHECK_LIB([readline], [readline]))
	if test "x$ac_cv_lib_readline_readline" = xyes; then :
		HAVE_LIBREADLINE=true
		AC_CACHE_CHECK([libedit rl_completion_entry_function bug], rl_cv_libedit_completion_entry_bug,
		tmp_CFLAGS="${CFLAGS}"
		CFLAGS+=" -Werror"
		AC_TRY_COMPILE(
			[
			#include <stdio.h>
			#include <readline/readline.h>
			],
			[
			const char *res = (*rl_completion_entry_function)(0,0);
			],
			[rl_cv_libedit_completion_entry_bug=no],
			[
			rl_cv_libedit_completion_entry_bug=yes
					AC_DEFINE_UNQUOTED([HAS_LIBEDIT_COMPLETION_ENTRY_BUG], [1],
									   [rl_completion_entry_function has the wrong return type])
			],
			)
		)
		CFLAGS="${tmp_CFLAGS}"
	fi
fi
AM_CONDITIONAL([HAVE_LIBREADLINE],$HAVE_LIBREADLINE)
AC_CHECK_FUNCS([rl_set_prompt])


dnl ###########################################################################

AC_SUBST([NYOCI_CPPFLAGS])

if test "${NYOCI_EMBEDDED+set}" = "set"
then AC_DEFINE_UNQUOTED([NYOCI_EMBEDDED], [$NYOCI_EMBEDDED], [.])
fi
if test "${NYOCI_SINGLETON+set}" = "set"
then AC_DEFINE_UNQUOTED([NYOCI_SINGLETON], [$NYOCI_SINGLETON], [.])
fi
if test "${NYOCI_PLAT_NET_POSIX_FAMILY+set}" = "set"
then AC_DEFINE_UNQUOTED([NYOCI_PLAT_NET_POSIX_FAMILY], [$NYOCI_PLAT_NET_POSIX_FAMILY], [.])
fi
if test "${NYOCI_AVOID_MALLOC+set}" = "set"
then AC_DEFINE_UNQUOTED([NYOCI_AVOID_MALLOC], [$NYOCI_AVOID_MALLOC], [.])
fi
if test "${NYOCI_AVOID_PRINTF+set}" = "set"
then AC_DEFINE_UNQUOTED([NYOCI_AVOID_PRINTF], [$NYOCI_AVOID_PRINTF], [.])
fi
if test "${NYOCI_MAX_VHOSTS+set}" = "set"
then AC_DEFINE_UNQUOTED([NYOCI_MAX_VHOSTS], [$NYOCI_MAX_VHOSTS], [.])
fi
if test "${NYOCI_CONF_TRANS_ENABLE_BLOCK2+set}" = "set"
then AC_DEFINE_UNQUOTED([NYOCI_CONF_TRANS_ENABLE_BLOCK2], [$NYOCI_CONF_TRANS_ENABLE_BLOCK2], [.])
fi
if test "${NYOCI_CONF_TRANS_ENABLE_OBSERVING+set}" = "set"
then AC_DEFINE_UNQUOTED([NYOCI_CONF_TRANS_ENABLE_OBSERVING], [$NYOCI_CONF_TRANS_ENABLE_OBSERVING], [.])
fi
if test "${NYOCI_MAX_OBSERVERS+set}" = "set"
then AC_DEFINE_UNQUOTED([NYOCI_MAX_OBSERVERS], [$NYOCI_MAX_OBSERVERS], [.])
fi
if test "${NYOCI_CONF_NODE_ROUTER+set}" = "set"
then AC_DEFINE_UNQUOTED([NYOCI_CONF_NODE_ROUTER], [$NYOCI_CONF_NODE_ROUTER], [.])
fi
if test "${NYOCI_USE_CASCADE_COUNT+set}" = "set"
then AC_DEFINE_UNQUOTED([NYOCI_USE_CASCADE_COUNT], [$NYOCI_USE_CASCADE_COUNT], [.])
fi


dnl ###########################################################################

AC_CONFIG_FILES(
	Makefile
	doxygen.cfg
	src/Makefile
	doc/Makefile
	src/libnyoci/Makefile
	src/libnyoci/libnyoci.pc
	src/libnyociextra/Makefile
	src/libnyociextra/libnyociextra.pc
	src/plugtest/Makefile
	src/nyocictl/Makefile
	src/examples/Makefile
	src/tests/Makefile
	src/missing/Makefile
	src/missing/strlcat/Makefile
	src/missing/strlcpy/Makefile
)

AC_OUTPUT

echo ""
echo "= Summary ====================================================================="
echo ""
echo "Network Platform ............... ${NYOCI_PLAT_NET-none}"
echo "DTLS Support ................... ${NYOCI_PLAT_TLS-none}"
echo "Embedded mode .................. ${enable_embedded-no}"
echo "Singleton instance ............. ${enable_singleton-${enable_embedded-no}}"
echo ""
echo "Building nyocictl .............. ${enable_nyocictl-yes}"
echo "Building libnyociextra ......... ${enable_libnyociextra-yes}"
echo "Building examples .............. ${enable_examples-yes}"
echo "Building plugtest .............. ${enable_plugtest-yes}"
echo ""

$HAVE_LIBREADLINE ||
	echo "warning: libreadline was disabled or not found, interactive nyocictl command line interface will not be enabled."
