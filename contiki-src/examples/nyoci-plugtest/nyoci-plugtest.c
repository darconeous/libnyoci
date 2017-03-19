/*	@file nyoci-plugtest.c
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

#include "nyoci-task.h"
#include "watchdog.h"
#include "net/ip/resolv.h"

#include <libnyoci/libnyoci.h>
#include <libnyociextra/nyoci-node-router.h>

#include <plugtest/plugtest-server.h>

PROCESS_NAME(nyoci_plugtest);
PROCESS(nyoci_plugtest, "LibNyoci Plugtest");

AUTOSTART_PROCESSES(
	&resolv_process,
	&nyoci_task,
	&nyoci_plugtest,
	NULL
);

PROCESS_THREAD(nyoci_plugtest, ev, data)
{
	static struct plugtest_server_s plugtest_server;
	static struct nyoci_node_s root_node;

	// Set up the root node.
	nyoci_node_init(&root_node,NULL,NULL);

	// Set up the node router.
	nyoci_set_default_request_handler(nyoci, &nyoci_node_router_handler, &root_node);

	PROCESS_BEGIN();

	plugtest_server_init(&plugtest_server,&root_node);

	PROCESS_END();
}
