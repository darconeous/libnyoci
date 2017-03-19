/*	@file nyoci-plat-uip.h
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

#ifndef NYOCI_nyoci_plat_uip_h
#define NYOCI_nyoci_plat_uip_h

#if !defined(NYOCI_INCLUDED_FROM_LIBNYOCI_H) && !defined(BUILDING_LIBNYOCI)
#error "Do not include this header directly, include <libnyoci/libnyoci.h> instead"
#endif

#include "net/ip/uip.h"

NYOCI_BEGIN_C_DECLS

#if UIP_CONF_IPV6
typedef uip_ip6addr_t nyoci_addr_t;
#else
typedef uip_ipaddr_t nyoci_addr_t;
#endif

typedef struct {
	nyoci_addr_t nyoci_addr;
	uint16_t nyoci_port;
} nyoci_sockaddr_t;

NYOCI_API_EXTERN struct uip_udp_conn* nyoci_plat_get_udp_conn(nyoci_t self);

NYOCI_BEGIN_C_DECLS

#include "nyoci-plat-net-func.h"

#endif
