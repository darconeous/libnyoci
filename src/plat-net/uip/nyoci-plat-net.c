/*	@file nyoci-plat-uip.c
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

#if CONTIKI
#include "contiki.h"
#include "net/ip/tcpip.h"
#include "net/ip/resolv.h"
#endif

#include <stdio.h>

#include "net/ip/uip-udp-packet.h"
#include "net/ip/uiplib.h"
extern uint16_t uip_slen;
extern void *uip_sappdata;

#define UIP_IP_BUF                          ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])

#if UIP_CONF_IPV6
#define UIP_UDP_BUF                        ((struct uip_udp_hdr *)&uip_buf[uip_l2_l3_hdr_len])
#else
#define UIP_UDP_BUF                        ((struct uip_udpip_hdr *)&uip_buf[UIP_LLH_LEN])
#endif

nyoci_status_t
nyoci_plat_join_standard_groups(nyoci_t self, int interface)
{
	NYOCI_SINGLETON_SELF_HOOK;
	// TODO: Implement me!
	return NYOCI_STATUS_NOT_IMPLEMENTED;
}

nyoci_t
nyoci_plat_init(nyoci_t self) {
	NYOCI_SINGLETON_SELF_HOOK;

#if UIP_CONF_IPV6
	{
		uip_ipaddr_t all_coap_nodes_addr;
		if(uiplib_ipaddrconv(
			COAP_MULTICAST_IP6_LL_ALLDEVICES,
			&all_coap_nodes_addr
		)) {
			uip_ds6_maddr_add(&all_coap_nodes_addr);
		}
	}
#endif

	return self;
}

nyoci_status_t
nyoci_plat_bind_to_port(
	nyoci_t self,
	nyoci_session_type_t type,
	uint16_t port
) {
	NYOCI_SINGLETON_SELF_HOOK;
	nyoci_status_t ret = NYOCI_STATUS_FAILURE;

	switch(type) {
	case NYOCI_SESSION_TYPE_UDP:
#if NYOCI_DTLS
	case NYOCI_SESSION_TYPE_DTLS:
#endif
#if NYOCI_TCP
	case NYOCI_SESSION_TYPE_TCP:
#endif
#if NYOCI_TLS
	case NYOCI_SESSION_TYPE_TLS:
#endif
		break;

	default:
		ret = NYOCI_STATUS_NOT_IMPLEMENTED;
		// Unsupported session type.
		goto bail;
	}

	// Set up the UDP port for listening.
	self->plat.udp_conn = udp_new(NULL, 0, NULL);
	uip_udp_bind(self->plat.udp_conn, htons(port));
	self->plat.udp_conn->rport = 0;

	ret = NYOCI_STATUS_OK;

bail:
	return ret;
}

void
nyoci_plat_finalize(nyoci_t self) {
	NYOCI_SINGLETON_SELF_HOOK;

	if(self->plat.udp_conn) {
		uip_udp_remove(self->plat.udp_conn);
	}
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


struct uip_udp_conn*
nyoci_plat_get_udp_conn(nyoci_t self) {
	NYOCI_SINGLETON_SELF_HOOK;
	return self->plat.udp_conn;
}

uint16_t
nyoci_plat_get_port(nyoci_t self) {
	NYOCI_SINGLETON_SELF_HOOK;
	return ntohs(self->plat.udp_conn->lport);
}


nyoci_status_t
nyoci_plat_outbound_start(nyoci_t self, uint8_t** data_ptr, coap_size_t *data_len)
{
	NYOCI_SINGLETON_SELF_HOOK;
	uint8_t *buffer;
	int space_remaining = UIP_BUFSIZE;

	uip_udp_conn = self->plat.udp_conn;
	buffer = (uint8_t*)uip_sappdata;

	if(buffer == (uint8_t*)self->inbound.packet) {
		// We want to preserve at least the headers from the inbound packet,
		// so we will put the outbound packet immediately after the last
		// header option of the inbound packet.
		buffer = (uint8_t*)self->inbound.content_ptr;

		// Fix the alignment for 32-bit platforms.
		buffer = (uint8_t*)((uintptr_t)((uint8_t*)self->outbound.packet+7)&~(uintptr_t)0x7);

		space_remaining -= (buffer-(uint8_t*)uip_buf);

		if (space_remaining-4<0) {
			buffer = (uint8_t*)uip_sappdata;
			space_remaining = UIP_BUFSIZE;
		}
	}

	if (data_ptr) {
		*data_ptr = buffer;
	}

	if (data_len) {
		*data_len = space_remaining;
	}

	return NYOCI_STATUS_OK;
}

nyoci_status_t
nyoci_plat_outbound_finish(nyoci_t self,const uint8_t* data_ptr, coap_size_t data_len, int flags)
{
	NYOCI_SINGLETON_SELF_HOOK;
	nyoci_status_t ret = NYOCI_STATUS_FAILURE;

	assert(uip_udp_conn == self->plat.udp_conn);

	uip_slen = data_len;

	require_action(uip_slen<NYOCI_MAX_PACKET_LENGTH, bail, ret = NYOCI_STATUS_MESSAGE_TOO_BIG);

	if (data_ptr != uip_sappdata) {
		memmove(
			uip_sappdata,
			data_ptr,
			uip_slen
		);
		data_ptr = (const uint8_t*)uip_sappdata;
	}

#if 0
	// TODO: For some reason this isn't working anymore. Investigate.
	if(self->is_responding) {
		// We are responding, let uIP handle preparing the packet.
	} else
#endif

	{	// Here we explicitly tickle UIP to send the packet.

		// Change the remote IP address temporarily.
		uip_ipaddr_copy(&uip_udp_conn->ripaddr, &self->plat.sockaddr_remote.nyoci_addr);
		nyoci_get_current_instance()->plat.udp_conn->rport = self->plat.sockaddr_remote.nyoci_port;

		uip_process(UIP_UDP_SEND_CONN);

#if UIP_CONF_IPV6_MULTICAST
		/* Let the multicast engine process the datagram before we send it */
		if (uip_is_addr_mcast_routable(&uip_udp_conn->ripaddr)) {
			UIP_MCAST6.out();
		}
#endif /* UIP_IPV6_MULTICAST */

		// TODO: This next part is somewhat contiki-ish. Abstract somehow?
#if UIP_CONF_IPV6
		tcpip_ipv6_output();
#else
		tcpip_output();
#endif

		// Since we just sent out packet, we need to zero out uip_slen
		// to prevent uIP from trying to send out a packet.
		uip_slen = 0;

		// Make our remote address unspecified again, so that we can continue
		// to receive traffic.
		memset(&nyoci_get_current_instance()->plat.udp_conn->ripaddr, 0, sizeof(uip_ipaddr_t));
		nyoci_get_current_instance()->plat.udp_conn->rport = 0;
	}

	ret = NYOCI_STATUS_OK;
bail:
	return ret;
}

// MARK: -

nyoci_status_t
nyoci_plat_wait(
	nyoci_t self, nyoci_cms_t cms
) {
	// This doesn't really make sense with UIP.
	return NYOCI_STATUS_OK;
}

nyoci_status_t
nyoci_plat_process(nyoci_t self) {
	NYOCI_SINGLETON_SELF_HOOK;

	if (!uip_udpconnection()) {
		goto bail;
	}

	if (uip_udp_conn != nyoci_plat_get_udp_conn(self)) {
		goto bail;
	}

	if(uip_newdata()) {
		memcpy(&self->plat.sockaddr_remote.nyoci_addr,&UIP_IP_BUF->srcipaddr,sizeof(nyoci_addr_t));
		self->plat.sockaddr_remote.nyoci_port = UIP_UDP_BUF->srcport;

		memcpy(&self->plat.sockaddr_local.nyoci_addr,&UIP_IP_BUF->destipaddr,sizeof(nyoci_addr_t));
		self->plat.sockaddr_local.nyoci_port = UIP_UDP_BUF->destport;

		nyoci_plat_set_session_type(NYOCI_SESSION_TYPE_UDP);

		nyoci_inbound_packet_process(self, uip_appdata, uip_datalen(), 0);
	} else if(uip_poll()) {
		nyoci_set_current_instance(self);
		nyoci_handle_timers(self);
	}

bail:
	nyoci_set_current_instance(NULL);
	self->is_responding = false;

	return 0;
}

nyoci_status_t
nyoci_plat_lookup_hostname(const char* hostname, nyoci_sockaddr_t* saddr, int flags)
{
	nyoci_status_t ret;
	memset(saddr, 0, sizeof(*saddr));

	ret = uiplib_ipaddrconv(
		hostname,
		&saddr->nyoci_addr
	) ? NYOCI_STATUS_OK : NYOCI_STATUS_HOST_LOOKUP_FAILURE;

#if NYOCI_CONF_USE_DNS
#if CONTIKI
	if(ret) {
		NYOCI_NON_RECURSIVE uip_ipaddr_t *temp = NULL;
		switch(resolv_lookup(hostname,&temp)) {
			case RESOLV_STATUS_CACHED:
				memcpy(&saddr->nyoci_addr, temp, sizeof(uip_ipaddr_t));
				ret = NYOCI_STATUS_OK;
				break;
			case RESOLV_STATUS_UNCACHED:
			case RESOLV_STATUS_EXPIRED:
				resolv_query(hostname);
			case RESOLV_STATUS_RESOLVING:
				ret = NYOCI_STATUS_WAIT_FOR_DNS;
				break;
			default:
			case RESOLV_STATUS_ERROR:
			case RESOLV_STATUS_NOT_FOUND:
				ret = NYOCI_STATUS_HOST_LOOKUP_FAILURE;
				break;
		}
	}
#else // CONTIKI
#error NYOCI_CONF_USE_DNS was set, but no DNS lookup mechamism is known!
#endif
#endif // NYOCI_CONF_USE_DNS

	require_noerr(ret,bail);

bail:
	return ret;
}


#if defined(CONTIKI)
nyoci_timestamp_t
nyoci_plat_cms_to_timestamp(
	nyoci_cms_t cms
) {
	return clock_time() + cms*CLOCK_SECOND/MSEC_PER_SEC;
}
nyoci_cms_t
nyoci_plat_timestamp_diff(nyoci_timestamp_t lhs, nyoci_timestamp_t rhs) {
	return (lhs - rhs)*MSEC_PER_SEC/CLOCK_SECOND;
}
nyoci_cms_t
nyoci_plat_timestamp_to_cms(nyoci_timestamp_t ts) {
	return nyoci_plat_timestamp_diff(ts, clock_time());
}
#endif
