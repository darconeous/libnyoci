/*	@file plugtest-server.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
**	@desc Plugtest Server Object Header
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

#include <libnyoci/libnyoci.h>
#include <libnyociextra/libnyociextra.h>

struct plugtest_server_s {
	struct nyoci_node_s test;
	struct nyoci_node_s seg1;
	struct nyoci_node_s seg2;
	struct nyoci_node_s seg3;
	struct nyoci_node_s query;
	struct nyoci_node_s separate;
	struct nyoci_node_s large;
	struct nyoci_node_s large_update;
	struct nyoci_node_s large_create;
	struct nyoci_node_s obs;
	struct nyoci_timer_s obs_timer;
	struct nyoci_observable_s observable;
};

extern nyoci_status_t plugtest_server_init(struct plugtest_server_s *self,nyoci_node_t root);
