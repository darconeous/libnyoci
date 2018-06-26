/*	@file nyoci-plat-bsd-internal.h
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

#ifndef NYOCI_nyoci_plat_bsd_internal_h
#define NYOCI_nyoci_plat_bsd_internal_h

#define __USE_GNU	1
#define __APPLE_USE_RFC_3542 1

#include "libnyoci.h"

#if NYOCI_DTLS
#include "nyoci-plat-tls.h"
#endif // if NYOCI_DTLS

#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef NYOCI_PLAT_NET_POSIX_FAMILY
#define NYOCI_PLAT_NET_POSIX_FAMILY		AF_INET6
#endif

#if NYOCI_SINGLETON
#define nyoci_internal_multicast_joinleave(self,...)		nyoci_internal_multicast_joinleave(__VA_ARGS__)
#endif


#define NYOCI_ADDR_NTOP(str, len, addr) inet_ntop(NYOCI_PLAT_NET_POSIX_FAMILY, addr , str, len-1)

#if NYOCI_PLAT_NET_POSIX_FAMILY == AF_INET6
#define ___nyoci_len		sin6_len
#define ___nyoci_family	sin6_family
#define NYOCI_IS_ADDR_MULTICAST(addrptr)	  (IN6_IS_ADDR_MULTICAST(addrptr) || (IN6_IS_ADDR_V4MAPPED(addrptr) && ((addrptr)->s6_addr[12] & 0xF0)==0xE0))
#define NYOCI_IS_ADDR_LOOPBACK(addrptr)	  (IN6_IS_ADDR_LOOPBACK(addrptr) || (IN6_IS_ADDR_V4MAPPED(addrptr) && (addrptr)->s6_addr[12] == 127))
#define NYOCI_IS_ADDR_UNSPECIFIED(addrptr) IN6_IS_ADDR_UNSPECIFIED(addrptr)

#define NYOCI_COAP_MULTICAST_ALLDEVICES_ADDR	COAP_MULTICAST_IP6_LL_ALLDEVICES

#ifdef IPV6_RECVPKTINFO
#define NYOCI_RECVPKTINFO IPV6_RECVPKTINFO
#endif
#ifdef IPV6_PKTINFO
#define NYOCI_PKTINFO IPV6_PKTINFO
#endif
#define NYOCI_IPPROTO IPPROTO_IPV6

#elif NYOCI_PLAT_NET_POSIX_FAMILY == AF_INET
#define ___nyoci_len		sin_len
#define ___nyoci_family	sin_family
#ifdef IP_RECVPKTINFO
#define NYOCI_RECVPKTINFO IP_RECVPKTINFO
#endif
#ifdef IP_PKTINFO
#define NYOCI_PKTINFO IP_PKTINFO
#endif
#define NYOCI_IPPROTO IPPROTO_IPV4

#define NYOCI_IS_ADDR_MULTICAST(addrptr) ((*(const uint8_t*)(addrptr)&0xF0)==224)
#define NYOCI_IS_ADDR_UNSPECIFIED(addrptr) (*(const uint32_t*)(addrptr)==0)
#define NYOCI_IS_ADDR_LOOPBACK(addrptr)	(*(const uint8_t*)(addrptr)==127)
#define NYOCI_COAP_MULTICAST_ALLDEVICES_ADDR	COAP_MULTICAST_IP4_ALLDEVICES

#else  // NYOCI_PLAT_NET_POSIX_FAMILY
#error Unsupported value for NYOCI_PLAT_NET_POSIX_FAMILY
#endif // NYOCI_PLAT_NET_POSIX_FAMILY

NYOCI_BEGIN_C_DECLS

struct nyoci_plat_s {
	int						mcfd_v6;	//!< For multicast
	int						mcfd_v4;	//!< For multicast

	int						fd_udp;

#if defined(NYOCI_PLAT_TLS)
	int						fd_dtls;
	void*					context_dtls;
	struct nyoci_plat_tls_s  ssl;
#endif

	void*					current_session;

	nyoci_sockaddr_t			sockaddr_local;
	nyoci_sockaddr_t			sockaddr_remote;
	nyoci_session_type_t     session_type;

#if NYOCI_PLAT_NET_POSIX_FAMILY==AF_INET6
	struct in6_pktinfo		pktinfo;
#elif NYOCI_PLAT_NET_POSIX_FAMILY==AF_INET
	struct in_pktinfo		pktinfo;
#endif

	char					outbound_packet_bytes[NYOCI_MAX_PACKET_LENGTH+1];
};


NYOCI_INTERNAL_EXTERN ssize_t sendtofrom(
	int fd,
	const void *data, size_t len, int flags,
	const struct sockaddr * saddr_to, socklen_t socklen_to,
	const struct sockaddr * saddr_from, socklen_t socklen_from
);

NYOCI_END_C_DECLS

#endif
