/*	@file nyoci-task.c
**	@author Robert Quattlebaum <darco@deepdarc.com>
**
**	Copyright (C) 2017  Robert Quattlebaum
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

#include "contiki.h"

#include <stdio.h>
#include <string.h>

#include <libnyoci/libnyoci.h>

#include "nyoci-task.h"

#include "net/ip/uip.h"
#include "net/ip/uip-udp-packet.h"
#include "sys/clock.h"
#include "watchdog.h"

#if DEBUG
#include <stdio.h>
#if __AVR__
#define PRINTF(FORMAT,args...) printf_P(PSTR(FORMAT),##args)
#else
#define PRINTF(...) printf(__VA_ARGS__)
#endif
#else
#define PRINTF(...)
#endif

#define UIP_IP_BUF                          ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])

#if UIP_CONF_IPV6
#define UIP_UDP_BUF                        ((struct uip_udp_hdr *)&uip_buf[uip_l2_l3_hdr_len])
#else
#define UIP_UDP_BUF                        ((struct uip_udpip_hdr *)&uip_buf[UIP_LLH_LEN])
#endif

PROCESS(nyoci_task, "CoAP Daemon");

PROCESS_THREAD(nyoci_task, ev, data)
{
	static struct etimer et;

	PROCESS_BEGIN();

	NYOCI_LIBRARY_VERSION_CHECK();

	PRINTF("Starting LibNyoci\n");

	if(!nyoci_create()) {
		PRINTF("Failed to start LibNyoci\n");
		goto bail;
	}

	if(!nyoci_plat_bind_to_port(nyoci, NYOCI_SESSION_TYPE_UDP, NYOCI_DEFAULT_PORT)) {
		PRINTF("Failed to bind to port\n");
		goto bail;
	}

	if(!nyoci_plat_get_udp_conn(nyoci)) {
		PRINTF("LibNyoci failed to create UDP conneciton!\n");
		goto bail;
	}

	PRINTF("LibNyoci started. UDP Connection = %p\n",nyoci_plat_get_udp_conn(nyoci));

	etimer_set(&et, 1);

	while(1) {
		PROCESS_WAIT_EVENT();

		if(ev == tcpip_event) {
			nyoci_plat_process(nyoci);
			etimer_set(&et, CLOCK_SECOND*nyoci_get_timeout(nyoci)/MSEC_PER_SEC+1);
		}

		if(etimer_expired(&et)) {
			tcpip_poll_udp(nyoci_plat_get_udp_conn(nyoci));
		} else {
			etimer_set(&et, CLOCK_SECOND*nyoci_get_timeout(nyoci)/MSEC_PER_SEC+1);
		}
	}

bail:
	PRINTF("Stopping LibNyoci\n");
	PROCESS_END();
}
