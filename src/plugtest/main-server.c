/*	@file main-server.c
**	@author Robert Quattlebaum <darco@deepdarc.com>
**	@desc Plugtest Server Entrypoint
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

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include "assert-macros.h"

#include <libnyoci/libnyoci.h>
#include <libnyociextra/libnyociextra.h>

#include <signal.h>
#include "plugtest-server.h"

bool gIsDone = false;
static sig_t gPreviousHandlerForSIGINT;
static sig_t gPreviousHandlerForSIGTERM;

static void
signal_SIGINT(int sig) {
	gIsDone = true;
	fprintf(stderr, "Caught SIGINT!\n");
	signal(SIGINT, gPreviousHandlerForSIGINT);
	gPreviousHandlerForSIGINT = NULL;
}

static void
signal_SIGTERM(int sig) {
	gIsDone = true;
	fprintf(stderr, "Caught SIGTERM!\n");
	signal(SIGTERM, gPreviousHandlerForSIGTERM);
	gPreviousHandlerForSIGTERM = NULL;
}

static void
signal_SIGHUP(int sig) {
	gIsDone = true;
	fprintf(stderr, "Caught SIGHUP!\n");
}

int
main(int argc, char * argv[]) {
	nyoci_t nyoci;
	struct plugtest_server_s plugtest_server = {};
	struct nyoci_node_s root_node = {};
	nyoci_status_t status;
	uint16_t port = COAP_DEFAULT_PORT;

	NYOCI_LIBRARY_VERSION_CHECK();

	if (argc > 1) {
		port = atoi(argv[1]);
	}

	gPreviousHandlerForSIGINT = signal(SIGINT, &signal_SIGINT);
	gPreviousHandlerForSIGTERM = signal(SIGINT, &signal_SIGTERM);
	signal(SIGHUP, &signal_SIGHUP);

	nyoci = nyoci_create();

	// Set up the root node.
	nyoci_node_init(&root_node,NULL,NULL);

	// Set up the node router.
	nyoci_set_default_request_handler(nyoci, &nyoci_node_router_handler, &root_node);

#if DEBUG
	fprintf(stderr,"DEBUG = %d\n",DEBUG);
#endif
#if VERBOSE_DEBUG
	fprintf(stderr,"VERBOSE_DEBUG = %d\n",VERBOSE_DEBUG);
#endif

	fprintf(stderr,"NYOCI_EMBEDDED = %d\n",NYOCI_EMBEDDED);
	fprintf(stderr,"NYOCI_SINGLETON = %d\n",NYOCI_SINGLETON);
	fprintf(stderr,"NYOCI_DEFAULT_PORT = %d\n",NYOCI_DEFAULT_PORT);
	fprintf(stderr,"NYOCI_MAX_PATH_LENGTH = %d\n",NYOCI_MAX_PATH_LENGTH);
	fprintf(stderr,"NYOCI_MAX_URI_LENGTH = %d\n",NYOCI_MAX_URI_LENGTH);
	fprintf(stderr,"NYOCI_MAX_PACKET_LENGTH = %d\n",(int)NYOCI_MAX_PACKET_LENGTH);
	fprintf(stderr,"NYOCI_MAX_CONTENT_LENGTH = %d\n",NYOCI_MAX_CONTENT_LENGTH);
	fprintf(stderr,"NYOCI_USE_CASCADE_COUNT = %d\n",NYOCI_USE_CASCADE_COUNT);
	fprintf(stderr,"NYOCI_MAX_CASCADE_COUNT = %d\n",NYOCI_MAX_CASCADE_COUNT);
	fprintf(stderr,"NYOCI_ADD_NEWLINES_TO_LIST_OUTPUT = %d\n",NYOCI_ADD_NEWLINES_TO_LIST_OUTPUT);
	fprintf(stderr,"NYOCI_AVOID_PRINTF = %d\n",NYOCI_AVOID_PRINTF);
	fprintf(stderr,"NYOCI_AVOID_MALLOC = %d\n",NYOCI_AVOID_MALLOC);
	fprintf(stderr,"NYOCI_CONF_USE_DNS = %d\n",NYOCI_CONF_USE_DNS);
	fprintf(stderr,"NYOCI_TRANSACTION_POOL_SIZE = %d\n",NYOCI_TRANSACTION_POOL_SIZE);
	fprintf(stderr,"NYOCI_CONF_MAX_ALLOCED_NODES = %d\n",NYOCI_CONF_MAX_ALLOCED_NODES);
	fprintf(stderr,"NYOCI_CONF_MAX_TIMEOUT = %d\n",NYOCI_CONF_MAX_TIMEOUT);
	fprintf(stderr,"NYOCI_CONF_DUPE_BUFFER_SIZE = %d\n",NYOCI_CONF_DUPE_BUFFER_SIZE);
	fprintf(stderr,"NYOCI_OBSERVATION_KEEPALIVE_INTERVAL = %d\n",NYOCI_OBSERVATION_KEEPALIVE_INTERVAL);
	fprintf(stderr,"NYOCI_OBSERVATION_DEFAULT_MAX_AGE = %d\n",NYOCI_OBSERVATION_DEFAULT_MAX_AGE);
	fprintf(stderr,"NYOCI_VARIABLE_MAX_VALUE_LENGTH = %d\n",NYOCI_VARIABLE_MAX_VALUE_LENGTH);
	fprintf(stderr,"NYOCI_VARIABLE_MAX_KEY_LENGTH = %d\n",NYOCI_VARIABLE_MAX_KEY_LENGTH);
#ifdef NYOCI_DEBUG_OUTBOUND_DROP_PERCENT
	fprintf(stderr,"NYOCI_DEBUG_OUTBOUND_DROP_PERCENT = %.1f%%\n",NYOCI_DEBUG_OUTBOUND_DROP_PERCENT*100.0);
#endif
#ifdef NYOCI_DEBUG_INBOUND_DROP_PERCENT
	fprintf(stderr,"NYOCI_DEBUG_INBOUND_DROP_PERCENT = %.1f%%\n",NYOCI_DEBUG_INBOUND_DROP_PERCENT*100.0);
#endif

	plugtest_server_init(&plugtest_server, &root_node);

	do {
		status = nyoci_plat_bind_to_port(nyoci, NYOCI_SESSION_TYPE_UDP, port);
		if (status != NYOCI_STATUS_OK) {
			port++;
		}
	} while (status != NYOCI_STATUS_OK && port != 0 && !gIsDone);

	if (status) {
		fprintf(stderr,"\nFailed to bind to port.\n");
		exit(EXIT_FAILURE);
	}
	fprintf(stderr,"\nPlugtest server listening on port %d.\n", port);

	// For some reason this next line is causing a unit test failure on Travis, OS X.
	// TODO: Investigate
	// nyoci_plat_join_standard_groups(nyoci, NYOCI_ANY_INTERFACE);

	while (!gIsDone) {
		nyoci_plat_wait(nyoci, CMS_DISTANT_FUTURE);
		nyoci_plat_process(nyoci);
	}

	return 0;
}
