/* src/config.h.  Generated from config.h.in by configure.  */
/* src/config.h.in.  Generated from configure.ac by autoheader.  */

/* rl_completion_entry_function has the wrong return type */
#define HAS_LIBEDIT_COMPLETION_ENTRY_BUG 1

/* Define to 1 if you have the `alloca' function. */
/* #undef HAVE_ALLOCA */

/* Define to 1 if you have the <alloca.h> header file. */
#define HAVE_ALLOCA_H 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the <errno.h> header file. */
#define HAVE_ERRNO_H 1

/* Define to 1 if you have the `fprintf' function. */
#define HAVE_FPRINTF 1

/* Define to 1 if the system has the `deprecated' function attribute */
#define HAVE_FUNC_ATTRIBUTE_DEPRECATED 1

/* Define to 1 if the system has the `pure' function attribute */
#define HAVE_FUNC_ATTRIBUTE_PURE 1

/* Define to 1 if you have the `getline' function. */
#define HAVE_GETLINE 1

/* Define to 1 if you have the `getloadavg' function. */
#define HAVE_GETLOADAVG 1

/* Define to 1 if you have the `gettimeofday' function. */
#define HAVE_GETTIMEOFDAY 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the `readline' library (-lreadline). */
#define HAVE_LIBREADLINE 1

/* Define to 1 if you have the `malloc' function. */
#define HAVE_MALLOC 1

/* Define to 1 if you have the `memcmp' function. */
#define HAVE_MEMCMP 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the `memset' function. */
#define HAVE_MEMSET 1

/* Set if OpenSSL is present */
/* #undef HAVE_OPENSSL */

/* Set if OpenSSL has DTLSv1_method() */
/* #undef HAVE_OPENSSL_DTLSV1_METHOD */

/* Set if OpenSSL has DTLS_method() */
/* #undef HAVE_OPENSSL_DTLS_METHOD */

/* Set if OpenSSL has SSL_CONF_CTX_new() */
/* #undef HAVE_OPENSSL_SSL_CONF_CTX_NEW */

/* Set if OpenSSL has SSL_CONF_finish() */
/* #undef HAVE_OPENSSL_SSL_CONF_FINISH */

/* Define to 1 if you have the `printf' function. */
#define HAVE_PRINTF 1

/* Define if you have POSIX threads libraries and header files. */
#define HAVE_PTHREAD 1

/* Have PTHREAD_PRIO_INHERIT. */
#define HAVE_PTHREAD_PRIO_INHERIT 1

/* Define to 1 if you have the `rl_set_prompt' function. */
#define HAVE_RL_SET_PROMPT 1

/* Define to 1 if you have the `setenv' function. */
#define HAVE_SETENV 1

/* Define to 1 if you have the `snprintf' function. */
#define HAVE_SNPRINTF 1

/* Define to 1 if you have the `sprintf' function. */
#define HAVE_SPRINTF 1

/* Define to 1 if you have the <stdarg.h> header file. */
#define HAVE_STDARG_H 1

/* Define to 1 if you have the <stdbool.h> header file. */
#define HAVE_STDBOOL_H 1

/* Define to 1 if you have the <stddef.h> header file. */
#define HAVE_STDDEF_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdio.h> header file. */
#define HAVE_STDIO_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `stpncpy' function. */
#define HAVE_STPNCPY 1

/* Define to 1 if you have the `strchr' function. */
#define HAVE_STRCHR 1

/* Define to 1 if you have the `strdup' function. */
#define HAVE_STRDUP 1

/* Define to 1 if you have the `strerror' function. */
#define HAVE_STRERROR 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strlcat' function. */
#define HAVE_STRLCAT 1

/* Define to 1 if you have the `strlcpy' function. */
#define HAVE_STRLCPY 1

/* Define to 1 if you have the `strndup' function. */
#define HAVE_STRNDUP 1

/* Define to 1 if you have the `strstr' function. */
#define HAVE_STRSTR 1

/* Define to 1 if you have the `strtol' function. */
#define HAVE_STRTOL 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if you have the `vsnprintf' function. */
#define HAVE_VSNPRINTF 1

/* Define to 1 if you have the `vsprintf' function. */
#define HAVE_VSPRINTF 1

/* Define to the sub-directory where libtool stores uninstalled libraries. */
#define LT_OBJDIR ".libs/"

/* . */
#define NYOCI_API_EXTERN __attribute__((visibility("default"))) extern

/* . */
/* #undef NYOCI_AVOID_MALLOC */

/* . */
/* #undef NYOCI_AVOID_PRINTF */

/* . */
/* #undef NYOCI_CONF_NODE_ROUTER */

/* . */
/* #undef NYOCI_CONF_TRANS_ENABLE_BLOCK2 */

/* . */
/* #undef NYOCI_CONF_TRANS_ENABLE_OBSERVING */

/* . */
/* #undef NYOCI_EMBEDDED */

/* . */
#define NYOCI_INTERNAL_EXTERN __attribute__((visibility("default"))) extern

/* . */
/* #undef NYOCI_MAX_OBSERVERS */

/* . */
/* #undef NYOCI_MAX_VHOSTS */

/* LibNyoci network abstraction */
#define NYOCI_PLAT_NET posix

/* . */
/* #undef NYOCI_PLAT_NET_POSIX_FAMILY */

/* LibNyoci TLS abstraction */
/* #undef NYOCI_PLAT_TLS */

/* . */
/* #undef NYOCI_SINGLETON */

/* . */
/* #undef NYOCI_USE_CASCADE_COUNT */

/* Name of package */
#define PACKAGE "libnyoci"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "https://github.com/darconeous/libnyoci/"

/* Define to the full name of this package. */
#define PACKAGE_NAME "LibNyoci"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "LibNyoci 0.07.00rc1"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "libnyoci"

/* Define to the home page for this package. */
#define PACKAGE_URL "http://libnyoci.org/"

/* Define to the version of this package. */
#define PACKAGE_VERSION "0.07.00rc1"

/* Define to necessary symbol if this constant uses a non-standard name on
   your system. */
/* #undef PTHREAD_CREATE_JOINABLE */

/* Source version */
#define SOURCE_VERSION "0.07.00rc1-6-g5ad1f3d"

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Define to 1 if you can safely include both <sys/time.h> and <time.h>. */
#define TIME_WITH_SYS_TIME 1

/* Enable extensions on AIX 3, Interix.  */
#ifndef _ALL_SOURCE
# define _ALL_SOURCE 1
#endif
/* Enable GNU extensions on systems that have them.  */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif
/* Enable threading extensions on Solaris.  */
#ifndef _POSIX_PTHREAD_SEMANTICS
# define _POSIX_PTHREAD_SEMANTICS 1
#endif
/* Enable extensions on HP NonStop.  */
#ifndef _TANDEM_SOURCE
# define _TANDEM_SOURCE 1
#endif
/* Enable general extensions on Solaris.  */
#ifndef __EXTENSIONS__
# define __EXTENSIONS__ 1
#endif


/* Version number of package */
#define VERSION "0.07.00rc1"

/* Define to 1 if on MINIX. */
/* #undef _MINIX */

/* Define to 2 if the system does not provide POSIX.1 features except with
   this defined. */
/* #undef _POSIX_1_SOURCE */

/* Define to 1 if you need to in order for `stat' and other things to work. */
/* #undef _POSIX_SOURCE */

/* Define to empty if `const' does not conform to ANSI C. */
/* #undef const */

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
/* #undef inline */
#endif

/* Define to `unsigned int' if <sys/types.h> does not define. */
/* #undef size_t */

/* Define to `int' if <sys/types.h> does not define. */
/* #undef ssize_t */

/* Define to empty if the keyword `volatile' does not work. Warning: valid
   code using `volatile' can become incorrect without. Disable with care. */
/* #undef volatile */
