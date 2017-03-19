/*	@file nyoci-plat-bsd.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
**
**	Copyright (C) 2017 Robert Quattlebaum
**
**	Permission is hereby granted, free of charge, to any person
**	obtaining a copy of this software and associated
**	documentation files (the "Software"), to deal in the
**	Software without restriction, including without limitation
**	the rights to use, copy, modify, merge, publish, distribute,
**	sublicense, and/or sell copies of the Software, and to
**	permit persons to whom the Software is furnished to do so,
**	subject to the following conditions:
**
**	The above copyright notice and this permission notice shall
**	be included in all copies or substantial portions of the
**	Software.
**
**	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
**	KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
**	WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
**	PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
**	OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
**	OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
**	OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
**	SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef NYOCI_nyoci_plat_bsd_h
#define NYOCI_nyoci_plat_bsd_h

#if !defined(NYOCI_INCLUDED_FROM_LIBNYOCI_H) && !defined(BUILDING_LIBNYOCI)
#error "Do not include this header directly, include <libnyoci/libnyoci.h> instead"
#endif

#define __USE_GNU	1
#define __APPLE_USE_RFC_3542 1

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/select.h>

#if NYOCI_SINGLETON
#define nyoci_plat_update_fdsets(self,...)		nyoci_plat_update_fdsets(__VA_ARGS__)
#endif

#ifndef NYOCI_PLAT_NET_POSIX_FAMILY
#define NYOCI_PLAT_NET_POSIX_FAMILY		AF_INET6
#endif

NYOCI_BEGIN_C_DECLS

#if NYOCI_PLAT_NET_POSIX_FAMILY == AF_INET6
typedef struct in6_addr nyoci_addr_t;
typedef struct sockaddr_in6 nyoci_sockaddr_t;
#define nyoci_addr		sin6_addr
#define nyoci_port		sin6_port
#elif NYOCI_PLAT_NET_POSIX_FAMILY == AF_INET
typedef struct in_addr nyoci_addr_t;
typedef struct sockaddr_in nyoci_sockaddr_t;
#define nyoci_addr		sin_addr
#define nyoci_port		sin_port
#else  // NYOCI_PLAT_NET_POSIX_FAMILY
#error Unsupported value for NYOCI_PLAT_NET_POSIX_FAMILY
#endif // NYOCI_PLAT_NET_POSIX_FAMILY

NYOCI_END_C_DECLS

#if defined(__KAME__)
#define NYOCI_SOCKADDR_INIT { sizeof(nyoci_sockaddr_t), NYOCI_PLAT_NET_POSIX_FAMILY }
#else
#define NYOCI_SOCKADDR_INIT { NYOCI_PLAT_NET_POSIX_FAMILY }
#endif

#include "nyoci-plat-net-func.h"

NYOCI_BEGIN_C_DECLS

//!	Gets the file descriptor for the UDP socket.
/*!	Useful for implementing asynchronous operation using select(),
**	poll(), or other async mechanisms. */
NYOCI_API_EXTERN int nyoci_plat_get_fd(nyoci_t self);

//! Support for `select()` style asynchronous operation
NYOCI_API_EXTERN nyoci_status_t nyoci_plat_update_fdsets(
	nyoci_t self,
	fd_set *read_fd_set,
	fd_set *write_fd_set,
	fd_set *error_fd_set,
	int *fd_count,
	nyoci_cms_t *timeout
);

NYOCI_END_C_DECLS

#endif
