/*	@file nyoci-plat-bsd.c
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

#if HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef VERBOSE_DEBUG
#define VERBOSE_DEBUG 0
#endif

#ifndef DEBUG
#define DEBUG VERBOSE_DEBUG
#endif

#include "assert-macros.h"

#include "libnyoci.h"

#include "nyoci-internal.h"
#include "nyoci-logging.h"
#include "nyoci-missing.h"

#include <stdio.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/cdefs.h>
#include <time.h>

#ifdef NYOCI_LWIP
	// Lightweight IP library <http://savannah.nongnu.org/projects/lwip/>
    #define ipv6_mreq ip6_mreq
	#define EAI_AGAIN TRY_AGAIN
#else
	#include <net/if.h>
#endif

#ifndef NYOCI_CAN_POLL
    #ifdef NYOCI_LWIP
        #define NYOCI_CAN_POLL 0
    #else
        #define NYOCI_CAN_POLL 1
	#endif
#endif

#ifndef NYOCI_CAN_SENDMSG
    #ifdef NYOCI_LWIP
        #define NYOCI_CAN_SENDMSG 0
    #else
        #define NYOCI_CAN_SENDMSG 1
	#endif
#endif

#if NYOCI_CAN_POLL
    #include <poll.h>
#endif

#ifndef SOCKADDR_HAS_LENGTH_FIELD
#if defined(__KAME__)
#define SOCKADDR_HAS_LENGTH_FIELD 1
#endif
#endif

#if NYOCI_SINGLETON
#define nyoci_internal_join_multicast_group(self,...)		nyoci_internal_join_multicast_group(__VA_ARGS__)
#endif


#ifdef NYOCI_LWIP
// lwIP does not have a gai_strerror() function
__unused static const char*
gai_strerror(int err)
{
	static const char* kMessages[] = {
		"EAI_NONAME",	// 200
		"EAI_SERVICE",	// 201
		"EAI_FAIL",		// 202
		"EAI_MEMORY",	// 203
		"EAI_FAMILY",	// 204
		NULL, NULL, NULL, NULL, NULL,
		"HOST_NOT_FOUND",// 210
		"NO_DATA",		// 211
		"NO_RECOVERY",	// 212
		"TRY_AGAIN",	// 213
	};
	if (err >= EAI_NONAME && err <= TRY_AGAIN) {
		const char *msg = kMessages[err - EAI_NONAME];
		if (msg)
			return msg;
	}
	static char buffer[20];
	sprintf(buffer, "netdb#%d", err);
	return buffer;
}
#endif


static struct addrinfo *
get_addresses(const char * address, int sockType, int sockFamily)
{
	struct addrinfo hints;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = sockFamily;
	hints.ai_socktype = sockType;

	if(address == NULL){
		hints.ai_flags = AI_PASSIVE;
	}

	int rv =0;
	struct addrinfo *addr = NULL;
	if ((rv = getaddrinfo(address, NULL, &hints, &addr)) != 0) {
		DEBUG_PRINTF("getaddrinfo: %s", gai_strerror(rv));
		return NULL;
	}

	return addr;
}

/** Struct to abstract use of ipv4 or ipv6 mreq*/
typedef struct multicast_group{
	int family;
	size_t group_size;
	union{
		struct ip_mreq ip4_group;
		struct ipv6_mreq ip6_group;
	} group;
} multicast_group_s;

static void fill_multicast_group(multicast_group_s * group, const struct sockaddr* addr, int interfaceIndex)
{
	bzero(group, sizeof(multicast_group_s));

	group->family = addr->sa_family;
	group->group_size = group->family == AF_INET ? sizeof(struct ip_mreq) : sizeof(struct ipv6_mreq);
    
	if(group->family == AF_INET){
		struct ip_mreq * mreq = &group->group.ip4_group;

		mreq->imr_interface.s_addr = INADDR_ANY;//TODO: enable specify the interface address
		mreq->imr_multiaddr = ((struct sockaddr_in *) addr)->sin_addr;
	}
	else{
		struct ipv6_mreq * mreq = &group->group.ip6_group;

#ifdef NYOCI_LWIP
		mreq->ipv6mr_interface = in6addr_any;//TODO: enable specify the interface address;
#else
		mreq->ipv6mr_interface = interfaceIndex;
#endif
		mreq->ipv6mr_multiaddr = ((struct sockaddr_in6*)addr)->sin6_addr;
	}

}

static nyoci_status_t
nyoci_internal_multicast_joinleave(nyoci_t self, const nyoci_sockaddr_t *group, int interface, bool join)
{
	NYOCI_SINGLETON_SELF_HOOK;
	nyoci_status_t status = NYOCI_STATUS_INVALID_ARGUMENT;

	if (NULL != group) {
		int ret = 0;
		sa_family_t family = ((const struct sockaddr *)group)->sa_family;

		multicast_group_s multicast;
		fill_multicast_group(&multicast, ((const struct sockaddr *)group), interface);

		const int fd	= self->plat.fd_udp;
		const int level = (family == AF_INET) ? IPPROTO_IP : IPPROTO_IPV6;
		const int opt   = (family == AF_INET)
								? (join ? IP_ADD_MEMBERSHIP		: IP_DROP_MEMBERSHIP)
								: (join ? IPV6_JOIN_GROUP		: IPV6_LEAVE_GROUP);

		ret = setsockopt(fd, level, opt, &multicast.group, (socklen_t)multicast.group_size);

		if (ret >= 0) {
			status = NYOCI_STATUS_OK;
		} else {
			status = NYOCI_STATUS_ERRNO;
		}
	}

	return status;
}

nyoci_status_t
nyoci_plat_multicast_join(nyoci_t self, const nyoci_sockaddr_t *group, int interface){
	return nyoci_internal_multicast_joinleave(self, group, interface, true);
}

nyoci_status_t
nyoci_plat_multicast_leave(nyoci_t self, const nyoci_sockaddr_t *group, int interface){
	return nyoci_internal_multicast_joinleave(self, group, interface, false);
}

static nyoci_status_t
nyoci_internal_join_multicast_group(nyoci_t self, const char* group, int interface)
{
	NYOCI_SINGLETON_SELF_HOOK;

	nyoci_status_t ret = NYOCI_STATUS_FAILURE;
	struct addrinfo* addr = get_addresses(group, SOCK_DGRAM, AF_UNSPEC);
	struct addrinfo* p;
	int count = 0;

	for (p = addr; p != NULL; p = p->ai_next) {
		ret = nyoci_plat_multicast_join(self, (const nyoci_sockaddr_t *)p->ai_addr, interface);

		if (ret == NYOCI_STATUS_OK) {
			count++;
		}
	}

	if (count > 0) {
		DEBUG_PRINTF("Joined group \"%s\"", group);
		ret = NYOCI_STATUS_OK;
	} else {
		DEBUG_PRINTF("Failed to join multicast group \"%s\" %s (%d)", group, nyoci_status_to_cstr(ret), errno);
	}

	freeaddrinfo(addr);

	return ret;
}

nyoci_status_t
nyoci_plat_join_standard_groups(nyoci_t self, int interface)
{
	nyoci_status_t ret;
	NYOCI_SINGLETON_SELF_HOOK;

#if NYOCI_PLAT_NET_POSIX_FAMILY == AF_INET6
	ret = nyoci_internal_join_multicast_group(self, COAP_MULTICAST_IP6_LL_ALLDEVICES, interface);
	if (ret != NYOCI_STATUS_OK) {
		return ret;
	}
#endif

	ret = nyoci_internal_join_multicast_group(self, COAP_MULTICAST_IP4_ALLDEVICES, interface);

	return ret;
}

nyoci_t
nyoci_plat_init(nyoci_t self) {
	NYOCI_SINGLETON_SELF_HOOK;

	self->plat.mcfd_v6 = -1;
	self->plat.mcfd_v4 = -1;
	self->plat.fd_udp = -1;
#if NYOCI_DTLS
	self->plat.fd_dtls = -1;
#endif

#if NYOCI_PLAT_NET_POSIX_FAMILY == AF_INET6
	if (self->plat.mcfd_v6 == -1) {
		self->plat.mcfd_v6 = socket(AF_INET6, SOCK_DGRAM, 0);
		check_errno(self->plat.mcfd_v6 >= 0);

		if (self->plat.mcfd_v6 >= 0 ) {
			int btrue = 1;
			setsockopt(
				self->plat.mcfd_v6,
				IPPROTO_IPV6,
				IPV6_MULTICAST_LOOP,
				&btrue,
				sizeof(btrue)
			);
		}
	}
#endif

	if (self->plat.mcfd_v4 == -1) {
		self->plat.mcfd_v4 = socket(AF_INET, SOCK_DGRAM, 0);
		check_errno(self->plat.mcfd_v4 >= 0);

		if (self->plat.mcfd_v4 >= 0) {
			int btrue = 1;
			setsockopt(
				self->plat.mcfd_v4,
				IPPROTO_IP,
				IP_MULTICAST_LOOP,
				&btrue,
				sizeof(btrue)
			);
		}
	}
	return self;
}

void
nyoci_plat_finalize(nyoci_t self) {
	NYOCI_SINGLETON_SELF_HOOK;

	if (self->plat.fd_udp >= 0) {
		close(self->plat.fd_udp);
	}

#if NYOCI_DTLS
	if (self->plat.fd_dtls >= 0) {
		close(self->plat.fd_dtls);
	}
#endif

#if NYOCI_PLAT_NET_POSIX_FAMILY == AF_INET6
	if (self->plat.mcfd_v6 >= 0) {
		close(self->plat.mcfd_v6);
	}
#endif

	if (self->plat.mcfd_v4 >= 0) {
		close(self->plat.mcfd_v4);
	}
}

int
nyoci_plat_get_fd(nyoci_t self) {
	NYOCI_SINGLETON_SELF_HOOK;
	return self->plat.fd_udp;
}

static uint16_t
get_port_for_fd(int fd) {
	nyoci_sockaddr_t saddr;
	socklen_t socklen = sizeof(saddr);
	if (fd < 0) {
		return 0;
	}
	getsockname(fd, (struct sockaddr*)&saddr, &socklen);
	return ntohs(saddr.nyoci_port);
}

uint16_t
nyoci_plat_get_port(nyoci_t self) {
	NYOCI_SINGLETON_SELF_HOOK;
	return get_port_for_fd(self->plat.fd_udp);
}

static nyoci_cms_t
monotonic_get_time_ms(void)
{
#if HAVE_CLOCK_GETTIME
	struct timespec tv = { 0 };
	int ret;

	ret = clock_gettime(CLOCK_MONOTONIC, &tv);

	return (nyoci_cms_t)(tv.tv_sec * MSEC_PER_SEC) + (nyoci_cms_t)(tv.tv_nsec / NSEC_PER_MSEC);
#else
	struct timeval tv = { 0 };
	gettimeofday(&tv, NULL);
	return (nyoci_cms_t)(tv.tv_sec * MSEC_PER_SEC) + (nyoci_cms_t)(tv.tv_usec / USEC_PER_MSEC);
#endif
}

nyoci_timestamp_t
nyoci_plat_cms_to_timestamp(
	nyoci_cms_t cms
) {
	return monotonic_get_time_ms() + cms;
}

nyoci_cms_t
nyoci_plat_timestamp_diff(nyoci_timestamp_t lhs, nyoci_timestamp_t rhs) {
	return lhs - rhs;
}

nyoci_cms_t
nyoci_plat_timestamp_to_cms(nyoci_timestamp_t ts) {
	return nyoci_plat_timestamp_diff(ts, monotonic_get_time_ms());
}

nyoci_status_t
nyoci_plat_bind_to_sockaddr(
	nyoci_t self,
	nyoci_session_type_t type,
	const nyoci_sockaddr_t* sockaddr
) {
	NYOCI_SINGLETON_SELF_HOOK;
	nyoci_status_t ret = NYOCI_STATUS_FAILURE;
	int fd = -1;

	switch(type) {
#if NYOCI_DTLS
	case NYOCI_SESSION_TYPE_DTLS:
		break;
#endif
#if NYOCI_TCP
	case NYOCI_SESSION_TYPE_TCP:
		break;
#endif
#if NYOCI_TLS
	case NYOCI_SESSION_TYPE_TLS:
		break;
#endif
	case NYOCI_SESSION_TYPE_UDP:
		break;

	default:
		ret = NYOCI_STATUS_NOT_IMPLEMENTED;
		// Unsupported session type.
		goto bail;
	}

	fd = socket(NYOCI_PLAT_NET_POSIX_FAMILY, SOCK_DGRAM, IPPROTO_UDP);

	require_action_string(fd >= 0, bail, ret = NYOCI_STATUS_ERRNO, strerror(errno));

#if defined(IPV6_V6ONLY) && NYOCI_PLAT_NET_POSIX_FAMILY==AF_INET6
	{
		int value = 0; /* explicitly allow ipv4 traffic too (required on bsd and some debian installations) */
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &value, sizeof(value)) < 0)
		{
			DEBUG_PRINTF("Setting IPV6_V6ONLY=0 on socket failed (%s)",strerror(errno));
		}
	}
#endif

	require_action_string(
		bind(fd, (struct sockaddr*)sockaddr, sizeof(*sockaddr)) == 0,
		bail,
		ret = NYOCI_STATUS_ERRNO,
		strerror(errno)
	);

#ifdef NYOCI_RECVPKTINFO
	{	// Handle sockopts.
		int value = 1;
		setsockopt(fd, NYOCI_IPPROTO, NYOCI_RECVPKTINFO, &value, sizeof(value));
	}
#endif

	// TODO: Fix this!
	switch(type) {
	case NYOCI_SESSION_TYPE_UDP:
		self->plat.fd_udp = fd;
		break;

#if NYOCI_DTLS
	case NYOCI_SESSION_TYPE_DTLS:
		DEBUG_PRINTF("DTLS Port %d", get_port_for_fd(fd));
		self->plat.fd_dtls = fd;
		break;
#endif

	default:
		ret = NYOCI_STATUS_NOT_IMPLEMENTED;
		// Unsupported session type.
		goto bail;
	}

	fd = -1;

	ret = NYOCI_STATUS_OK;

bail:
	if (fd >= 0) {
		close(fd);
	}
	return ret;
}


nyoci_status_t
nyoci_plat_bind_to_port(
	nyoci_t self,
	nyoci_session_type_t type,
	uint16_t port
) {
	NYOCI_SINGLETON_SELF_HOOK;

	nyoci_sockaddr_t saddr = {
#if SOCKADDR_HAS_LENGTH_FIELD
		.___nyoci_len		= sizeof(nyoci_sockaddr_t),
#endif
		.___nyoci_family	= NYOCI_PLAT_NET_POSIX_FAMILY,
		.nyoci_port		= htons(port),
	};

	return nyoci_plat_bind_to_sockaddr(self, type, &saddr);
}

#if NYOCI_CAN_POLL
int
nyoci_plat_update_pollfds(
	nyoci_t self,
	struct pollfd fds[],
	int maxfds
) {
	int ret = 0;
	NYOCI_SINGLETON_SELF_HOOK;

	require_quiet(maxfds > 0, bail);

	assert(fds != NULL);

	if (self->plat.fd_udp > 0) {
		if (ret <= maxfds) {
			fds->fd = self->plat.fd_udp;
			fds->events = POLLIN | POLLHUP;
			fds->revents = 0;
			fds++;
			maxfds--;
		}
		ret++;
	}

#if NYOCI_DTLS
	if (self->plat.fd_dtls > 0) {
		if (ret <= maxfds) {
			fds->fd = self->plat.fd_dtls;
			fds->events = POLLIN | POLLHUP;
			fds->revents = 0;
			fds++;
			maxfds--;
		}
		ret++;
	}
#endif // NYOCI_DTLS

bail:
	return ret;
}
#endif //NYOCI_CAN_POLL

nyoci_status_t
nyoci_plat_update_fdsets(
	nyoci_t self,
	fd_set *read_fd_set,
	fd_set *write_fd_set,
	fd_set *error_fd_set,
	int *fd_count,
	nyoci_cms_t *timeout
) {
	NYOCI_SINGLETON_SELF_HOOK;
	nyoci_status_t ret = NYOCI_STATUS_OK;

	if (self->plat.fd_udp > 0) {
		if (read_fd_set) {
			FD_SET(self->plat.fd_udp, read_fd_set);
		}

		if (error_fd_set) {
			FD_SET(self->plat.fd_udp, error_fd_set);
		}

		if (fd_count && (*fd_count <= self->plat.fd_udp)) {
			*fd_count = self->plat.fd_udp + 1;
		}
	}

#if NYOCI_DTLS
	if (self->plat.fd_dtls > 0) {
		if (read_fd_set) {
			FD_SET(self->plat.fd_dtls, read_fd_set);
		}

		if (error_fd_set) {
			FD_SET(self->plat.fd_dtls, error_fd_set);
		}

		if (fd_count && (*fd_count <= self->plat.fd_dtls)) {
			*fd_count = self->plat.fd_dtls + 1;
		}
	}
#endif

	if (timeout) {
		nyoci_cms_t tmp = nyoci_get_timeout(self);

		if (tmp <= *timeout) {
			*timeout = tmp;
		}
	}

	return ret;
}


ssize_t
sendtofrom(
	int fd,
	const void *data, size_t len, int flags,
	const struct sockaddr * saddr_to, socklen_t socklen_to,
	const struct sockaddr * saddr_from, socklen_t socklen_from
)
{
	ssize_t ret = -1;

	if (NYOCI_IS_ADDR_MULTICAST(&((nyoci_sockaddr_t*)saddr_from)->nyoci_addr)) {
		saddr_from = NULL;
		socklen_from = 0;
	}

	if ((socklen_from == 0)
		|| (saddr_from == NULL)
		|| (saddr_from->sa_family != saddr_to->sa_family)
	) {
		ret = sendto(
			fd,
			data,
			len,
			0,
			(struct sockaddr *)saddr_to,
			socklen_to
		);
		check(ret>0);
	} else {
#if NYOCI_CAN_SENDMSG
		struct iovec iov = { (void *)data, len };
		uint8_t cmbuf[CMSG_SPACE(sizeof (struct in6_pktinfo))];
		struct cmsghdr *scmsgp;
		struct msghdr msg = {
			.msg_name = (void*)saddr_to,
			.msg_namelen = socklen_to,
			.msg_iov = &iov,
			.msg_iovlen = 1,
			.msg_control = cmbuf,
			.msg_controllen = sizeof(cmbuf),
		};

#if defined(AF_INET6)
		if (saddr_to->sa_family == AF_INET6) {
			struct in6_pktinfo *pktinfo;
			scmsgp = CMSG_FIRSTHDR(&msg);
			scmsgp->cmsg_level = IPPROTO_IPV6;
			scmsgp->cmsg_type = IPV6_PKTINFO;
			scmsgp->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
			pktinfo = (struct in6_pktinfo *)(CMSG_DATA(scmsgp));

			pktinfo->ipi6_addr = ((struct sockaddr_in6*)saddr_from)->sin6_addr;
			pktinfo->ipi6_ifindex = ((struct sockaddr_in6*)saddr_from)->sin6_scope_id;
		} else
#endif

		if (saddr_to->sa_family == AF_INET) {
			struct in_pktinfo *pktinfo;
			scmsgp = CMSG_FIRSTHDR(&msg);
			scmsgp->cmsg_level = IPPROTO_IP;
			scmsgp->cmsg_type = IP_PKTINFO;
			scmsgp->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
			pktinfo = (struct in_pktinfo *)(CMSG_DATA(scmsgp));

			pktinfo->ipi_spec_dst = ((struct sockaddr_in*)saddr_to)->sin_addr;
			pktinfo->ipi_addr = ((struct sockaddr_in*)saddr_from)->sin_addr;
			pktinfo->ipi_ifindex = 0;
		}
        
		ret = sendmsg(fd, &msg, flags);

		check(ret > 0);
		check_string(ret >= 0, strerror(errno));
#else // !NYOCI_CAN_SENDMSG
		abort(); //TODO
#endif // NYOCI_CAN_SENDMSG
	}

	return ret;
}

nyoci_status_t
nyoci_plat_set_remote_hostname_and_port(const char* hostname, uint16_t port)
{
	nyoci_status_t ret;
	NYOCI_NON_RECURSIVE nyoci_sockaddr_t saddr;

	DEBUG_PRINTF("Outbound: Dest host [%s]:%d",hostname,port);

#if NYOCI_DTLS
	nyoci_plat_tls_set_remote_hostname(hostname);
#endif

	// Check to see if this host is a group we know about.
	if (strcasecmp(hostname, COAP_MULTICAST_STR_ALLDEVICES) == 0) {
		hostname = NYOCI_COAP_MULTICAST_ALLDEVICES_ADDR;
	}

	ret = nyoci_plat_lookup_hostname(hostname, &saddr, NYOCI_LOOKUP_HOSTNAME_FLAG_DEFAULT);
	require_noerr(ret, bail);

	saddr.nyoci_port = htons(port);

	nyoci_plat_set_remote_sockaddr(&saddr);

bail:
	return ret;
}


void
nyoci_plat_set_remote_sockaddr(const nyoci_sockaddr_t* addr)
{
	nyoci_t const self = nyoci_get_current_instance();

	if (addr) {
		self->plat.sockaddr_remote = *addr;
	} else {
		memset(&self->plat.sockaddr_remote,0,sizeof(self->plat.sockaddr_remote));
	}
}

void
nyoci_plat_set_local_sockaddr(const nyoci_sockaddr_t* addr)
{
	nyoci_t const self = nyoci_get_current_instance();

	if (addr) {
		self->plat.sockaddr_local = *addr;
	} else {
		memset(&self->plat.sockaddr_local,0,sizeof(self->plat.sockaddr_local));
	}
}

void
nyoci_plat_set_session_type(nyoci_session_type_t type)
{
	nyoci_t const self = nyoci_get_current_instance();

	self->plat.session_type = type;
}


const nyoci_sockaddr_t*
nyoci_plat_get_remote_sockaddr(void)
{
	return &nyoci_get_current_instance()->plat.sockaddr_remote;
}

const nyoci_sockaddr_t*
nyoci_plat_get_local_sockaddr(void)
{
	return &nyoci_get_current_instance()->plat.sockaddr_local;
}

nyoci_session_type_t
nyoci_plat_get_session_type(void)
{
	return nyoci_get_current_instance()->plat.session_type;
}

nyoci_status_t
nyoci_plat_outbound_start(nyoci_t self, uint8_t** data_ptr, coap_size_t *data_len)
{
	NYOCI_SINGLETON_SELF_HOOK;
	if (data_ptr) {
		*data_ptr = (uint8_t*)self->plat.outbound_packet_bytes;
	}
	if (data_len) {
		*data_len = sizeof(self->plat.outbound_packet_bytes);
	}
	self->outbound.packet = (struct coap_header_s*)self->plat.outbound_packet_bytes;
	return NYOCI_STATUS_OK;
}


nyoci_status_t
nyoci_plat_outbound_finish(nyoci_t self,const uint8_t* data_ptr, coap_size_t data_len, int flags)
{
	NYOCI_SINGLETON_SELF_HOOK;
	nyoci_status_t ret = NYOCI_STATUS_FAILURE;
	ssize_t sent_bytes = -1;
	int fd;

#if NYOCI_DTLS
	if (nyoci_plat_get_session_type() == NYOCI_SESSION_TYPE_DTLS) {
		ret = nyoci_plat_tls_outbound_packet_process(self, data_ptr, data_len);
	} else
#endif
	if (nyoci_plat_get_session_type() == NYOCI_SESSION_TYPE_UDP) {
		fd = nyoci_get_current_instance()->plat.fd_udp;

		assert(fd >= 0);

		require(data_len > 0, bail);

#if VERBOSE_DEBUG
		{
			char addr_str[50] = "???";
			uint16_t port = ntohs(nyoci_plat_get_remote_sockaddr()->nyoci_port);
			NYOCI_ADDR_NTOP(addr_str,sizeof(addr_str),&nyoci_plat_get_remote_sockaddr()->nyoci_addr);
			DEBUG_PRINTF("nyoci(%p): Outbound packet to [%s]:%d", self,addr_str,(int)port);
			coap_dump_header(
				NYOCI_DEBUG_OUT_FILE,
				"Outbound:\t",
				(struct coap_header_s*)data_ptr,
				(coap_size_t)data_len
			);
		}
#endif

		sent_bytes = sendtofrom(
			fd,
			data_ptr,
			data_len,
			0,
			(struct sockaddr *)nyoci_plat_get_remote_sockaddr(),
			sizeof(nyoci_sockaddr_t),
			(struct sockaddr *)nyoci_plat_get_local_sockaddr(),
			sizeof(nyoci_sockaddr_t)
		);

		require_action_string(
			(sent_bytes >= 0),
			bail, ret = NYOCI_STATUS_ERRNO, strerror(errno)
		);

		require_action_string(
			(sent_bytes == data_len),
			bail, ret = NYOCI_STATUS_FAILURE, "sendto() returned less than len"
		);

		ret = NYOCI_STATUS_OK;

	} else {
		ret = NYOCI_STATUS_NOT_IMPLEMENTED;
	}
bail:
	return ret;
}

// MARK: -

nyoci_status_t
nyoci_plat_wait(
	nyoci_t self, nyoci_cms_t cms
) {
	NYOCI_SINGLETON_SELF_HOOK;
	nyoci_status_t ret = NYOCI_STATUS_OK;
	int descriptors_ready;

#if NYOCI_CAN_POLL
	struct pollfd polls[4];
	int poll_count;

	poll_count = nyoci_plat_update_pollfds(self, polls, sizeof(polls)/sizeof(*polls));

	if (poll_count > (int)(sizeof(polls)/sizeof(*polls))) {
		poll_count = sizeof(polls)/sizeof(*polls);
	}

	if(cms >= 0) {
		cms = MIN(cms, nyoci_get_timeout(self));
	} else {
		cms = nyoci_get_timeout(self);
	}

	errno = 0;

	descriptors_ready = poll(polls, poll_count, cms);

#else // !NYOCI_CAN_POLL
	fd_set reads, writes, errors;
	int fdCount = 0;
	FD_ZERO(&reads);
	FD_ZERO(&writes);
	FD_ZERO(&errors);
	if (cms <= 0) {
		cms = 3600 * MSEC_PER_SEC;
	}
	ret = nyoci_plat_update_fdsets(self, &reads, &writes, &errors, &fdCount, &cms);
	if (ret != NYOCI_STATUS_OK)
		goto bail;
	struct timeval timeout = {cms / 1000, (cms % 1000) * 1000};

	DEBUG_PRINTF("Calling select for %dms ...", cms);
	descriptors_ready = select(fdCount, &reads, &writes, &errors, &timeout);
	DEBUG_PRINTF("...select returned (%d events)", descriptors_ready);
#endif // NYOCI_CAN_POLL

	// Ensure that poll did not fail with an error.
	require_action_string(descriptors_ready != -1,
		bail,
		ret = NYOCI_STATUS_ERRNO,
		strerror(errno)
	);

	if (descriptors_ready == 0) {
		ret = NYOCI_STATUS_TIMEOUT;
	}

bail:
	return ret;
}

// wraps an IPv4 address in its IPv6 equivalent
static struct sockaddr_in6
wrapIPv4Address(const struct sockaddr_in *addr4)
{
	struct sockaddr_in6 addr6 = {
		.sin6_len = sizeof(struct sockaddr_in6),
		.sin6_family = AF_INET6,
		.sin6_port = addr4->sin_port
	};
	addr6.sin6_addr.s6_addr[10] = addr6.sin6_addr.s6_addr[11] = 0xFF;
	memcpy(&addr6.sin6_addr.s6_addr[12], &addr4->sin_addr, 4);
	return addr6;
}

static nyoci_status_t
nyoci_plat_process_fd(nyoci_t self, int fd)
{
	nyoci_status_t ret = 0;
	char packet[NYOCI_MAX_PACKET_LENGTH+1];
	nyoci_sockaddr_t remote_saddr = {};
	nyoci_sockaddr_t local_saddr = {};
	ssize_t packet_len = 0;

#if NYOCI_CAN_POLL
	char cmbuf[0x100];
	struct iovec iov = { packet, NYOCI_MAX_PACKET_LENGTH };
	struct msghdr msg = {
		.msg_name = &remote_saddr,
		.msg_namelen = sizeof(remote_saddr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cmbuf,
		.msg_controllen = sizeof(cmbuf),
	};
	struct cmsghdr *cmsg;

	packet_len = recvmsg(fd, &msg, 0);

	require_action(packet_len > 0, bail, ret = NYOCI_STATUS_ERRNO);

	packet[packet_len] = 0;

	for (
		 cmsg = CMSG_FIRSTHDR(&msg);
		 cmsg != NULL;
		 cmsg = CMSG_NXTHDR(&msg, cmsg)
		 ) {
		if (cmsg->cmsg_level != NYOCI_IPPROTO
			|| cmsg->cmsg_type != NYOCI_PKTINFO
			) {
			continue;
		}

		// Preinitialize some of the fields.
		local_saddr = remote_saddr;

#if NYOCI_PLAT_NET_POSIX_FAMILY==AF_INET6
		struct in6_pktinfo *pi = (struct in6_pktinfo *)CMSG_DATA(cmsg);
		local_saddr.nyoci_addr = pi->ipi6_addr;
		local_saddr.sin6_scope_id = pi->ipi6_ifindex;

#elif NYOCI_PLAT_NET_POSIX_FAMILY==AF_INET
		struct in_pktinfo *pi = (struct in_pktinfo *)CMSG_DATA(cmsg);
		local_saddr.nyoci_addr = pi->ipi_addr;
#endif

		local_saddr.nyoci_port = htons(get_port_for_fd(fd));

		self->plat.pktinfo = *pi;
	}

#else // !NYOCI_CAN_POLL
	socklen_t addr_len = sizeof(remote_saddr);
	packet_len = recvfrom(fd, packet, NYOCI_MAX_PACKET_LENGTH, 0,
						  (struct sockaddr*)&remote_saddr, &addr_len);
	require_action(packet_len > 0, bail, ret = NYOCI_STATUS_ERRNO);

	packet[packet_len] = 0;

	addr_len = sizeof(local_saddr);
	getsockname(fd, (struct sockaddr*)&local_saddr, &addr_len);
#endif // NYOCI_CAN_POLL

#if NYOCI_PLAT_NET_POSIX_FAMILY == AF_INET6
	if (remote_saddr.sin6_family == AF_INET) {
		// If the incoming address is an IPv4 address (which happens on lwIP), convert it to a
		// v4-mapped IPv6 address since that's the form we're expecting.
		remote_saddr = wrapIPv4Address((struct sockaddr_in*)&remote_saddr);
	}
#endif

	nyoci_set_current_instance(self);
	nyoci_plat_set_remote_sockaddr(&remote_saddr);
	nyoci_plat_set_local_sockaddr(&local_saddr);

	if (self->plat.fd_udp == fd) {
		nyoci_plat_set_session_type(NYOCI_SESSION_TYPE_UDP);

		ret = nyoci_inbound_packet_process(self, packet, (coap_size_t)packet_len, 0);
		require_noerr(ret, bail);

#if NYOCI_DTLS
	} else if (self->plat.fd_dtls == fd) {
		nyoci_plat_set_session_type(NYOCI_SESSION_TYPE_DTLS);
		nyoci_plat_tls_inbound_packet_process(
											  self,
											  packet,
											  (coap_size_t)packet_len
											  );
#endif
	}
bail:
	return ret;
}

nyoci_status_t
nyoci_plat_process(
	nyoci_t self
) {
	NYOCI_SINGLETON_SELF_HOOK;
	nyoci_status_t ret = 0;

#if NYOCI_CAN_POLL
	int tmp;
	struct pollfd polls[4];
	int poll_count;

	poll_count = nyoci_plat_update_pollfds(self, polls, sizeof(polls)/sizeof(polls[0]));

	if (poll_count > (int)(sizeof(polls)/sizeof(*polls))) {
		poll_count = sizeof(polls)/sizeof(*polls);
	}

	errno = 0;

	tmp = poll(polls, poll_count, 0);

	// Ensure that poll did not fail with an error.
	require_action_string(
		errno == 0,
		bail,
		ret = NYOCI_STATUS_ERRNO,
		strerror(errno)
	);

	if(tmp > 0) {
		for (tmp = 0; tmp < poll_count; tmp++) {
			if (polls[tmp].revents) {
				ret = nyoci_plat_process_fd(self, polls[tmp].fd);
				if (ret != NYOCI_STATUS_OK)
					goto bail;
			}
		}
	}

#else // !NYOCI_CAN_POLL
	fd_set reads, writes, errors;
	int fdCount = 0;
	FD_ZERO(&reads);
    FD_ZERO(&writes);
	FD_ZERO(&errors);
	ret = nyoci_plat_update_fdsets(self, &reads, &writes, &errors, &fdCount, NULL);
	if (ret != NYOCI_STATUS_OK)
		goto bail;

	struct timeval zero_timeout = {0, 0};
	int descriptors_ready = select(fdCount, &reads, &writes, &errors, &zero_timeout);
	require_action_string(
						  descriptors_ready >= 0,
						  bail,
						  ret = NYOCI_STATUS_ERRNO,
						  strerror(errno)
						  );

	if (descriptors_ready > 0) {
		for (int fd = 0; fd < fdCount; ++fd) {
			if (FD_ISSET(fd, &reads)) {
				ret = nyoci_plat_process_fd(self, fd);
				if (ret != NYOCI_STATUS_OK)
					goto bail;
			}
		}
	}
#endif // NYOCI_CAN_POLL

	nyoci_handle_timers(self);

bail:
	nyoci_set_current_instance(NULL);
	self->is_responding = false;
	return ret;
}

nyoci_status_t
nyoci_plat_lookup_hostname(const char* hostname, nyoci_sockaddr_t* saddr, int flags)
{
	nyoci_status_t ret;
	struct addrinfo hint = {
		.ai_flags		= AI_ADDRCONFIG,
		.ai_family		= AF_UNSPEC,
	};

	struct addrinfo *results = NULL;
	struct addrinfo *iter = NULL;

	if (flags & NYOCI_LOOKUP_HOSTNAME_FLAG_NUMERIC) {
		hint.ai_flags |= AI_NUMERICHOST;
	}

#if NYOCI_PLAT_NET_POSIX_FAMILY != AF_INET6
	hint.ai_family = NYOCI_PLAT_NET_POSIX_FAMILY;
#endif

	if ((flags & (NYOCI_LOOKUP_HOSTNAME_FLAG_IPV4_ONLY|NYOCI_LOOKUP_HOSTNAME_FLAG_IPV6_ONLY)) == (NYOCI_LOOKUP_HOSTNAME_FLAG_IPV4_ONLY|NYOCI_LOOKUP_HOSTNAME_FLAG_IPV6_ONLY)) {
		ret = NYOCI_STATUS_INVALID_ARGUMENT;
		goto bail;
	} else if ((flags & NYOCI_LOOKUP_HOSTNAME_FLAG_IPV4_ONLY) == NYOCI_LOOKUP_HOSTNAME_FLAG_IPV4_ONLY) {
		hint.ai_family = AF_INET;
	} else if ((flags & NYOCI_LOOKUP_HOSTNAME_FLAG_IPV6_ONLY) == NYOCI_LOOKUP_HOSTNAME_FLAG_IPV6_ONLY) {
		hint.ai_family = AF_INET6;
	}

	memset(saddr, 0, sizeof(*saddr));
	saddr->___nyoci_family = NYOCI_PLAT_NET_POSIX_FAMILY;

#if SOCKADDR_HAS_LENGTH_FIELD
	saddr->___nyoci_len = sizeof(*saddr);
#endif

	int error = getaddrinfo(hostname, NULL, &hint, &results);

#if NYOCI_PLAT_NET_POSIX_FAMILY==AF_INET6
	if(error && (inet_addr(hostname) != INADDR_NONE)) {
		char addr_v4mapped_str[8 + strlen(hostname)];
		hint.ai_family = AF_INET6;
		hint.ai_flags = AI_ALL | AI_V4MAPPED;
		strcpy(addr_v4mapped_str,"::ffff:");
		strcat(addr_v4mapped_str,hostname);
		error = getaddrinfo(addr_v4mapped_str,
			NULL,
			&hint,
			&results
		);
	}
#endif

	if (EAI_AGAIN == error) {
		ret = NYOCI_STATUS_WAIT_FOR_DNS;
		goto bail;
	}

#ifdef TM_EWOULDBLOCK
	if (TM_EWOULDBLOCK == error) {
		ret = NYOCI_STATUS_WAIT_FOR_DNS;
		goto bail;
	}
#endif

	require_action_string(
		!error,
		bail,
		ret = NYOCI_STATUS_HOST_LOOKUP_FAILURE,
		gai_strerror(error)
	);

	// Move to the first recognized result
	for(iter = results;iter && (iter->ai_family!=AF_INET6 && iter->ai_family!=AF_INET);iter=iter->ai_next);

	require_action(
		iter != NULL,
		bail,
		ret = NYOCI_STATUS_HOST_LOOKUP_FAILURE
	);

#if NYOCI_PLAT_NET_POSIX_FAMILY==AF_INET6
	if(iter->ai_family == AF_INET) {
		struct sockaddr_in *v4addr = (void*)iter->ai_addr;
		saddr->sin6_addr.s6_addr[10] = 0xFF;
		saddr->sin6_addr.s6_addr[11] = 0xFF;
		memcpy(&saddr->sin6_addr.s6_addr[12], &v4addr->sin_addr.s_addr, 4);
	} else
#endif
	if(iter->ai_family == NYOCI_PLAT_NET_POSIX_FAMILY) {
		memcpy(saddr, iter->ai_addr, iter->ai_addrlen);
	}

	// TODO: I don't think this goes here...
	if(NYOCI_IS_ADDR_MULTICAST(&saddr->nyoci_addr)) {
		nyoci_t const self = nyoci_get_current_instance();
		if (self != NULL && self->outbound.packet != NULL) {
			check(self->outbound.packet->tt != COAP_TRANS_TYPE_CONFIRMABLE);
			if(self->outbound.packet->tt == COAP_TRANS_TYPE_CONFIRMABLE) {
				self->outbound.packet->tt = COAP_TRANS_TYPE_NONCONFIRMABLE;
			}
		}
	}

	ret = NYOCI_STATUS_OK;

bail:
	if (results) {
		freeaddrinfo(results);
	}

	return ret;
}
