/*!	@page test-issue-21 test-issue-21.c: Verify correct handling of URL path
**
**	https://github.com/darconeous/libnyoci/issues/21
**
**	@include test-issue-21.c
**
*/

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include "assert-macros.h"
#include <stdio.h>
#include <stdbool.h>
#include <libnyoci/libnyoci.h>
#include <libnyociextra/nyoci-node-router.h>

bool gIsFinished = false;

static nyoci_status_t
request_handler(void* context)
{
	printf("Got a request!\n");

	// Only handle GET requests for now.
	if(nyoci_inbound_get_code() != COAP_METHOD_GET) {
		return NYOCI_STATUS_NOT_IMPLEMENTED;
	}

	// Begin describing the response.
	nyoci_outbound_begin_response(COAP_RESULT_205_CONTENT);

	nyoci_outbound_add_option_uint(
		COAP_OPTION_CONTENT_TYPE,
		COAP_CONTENT_TYPE_TEXT_PLAIN
	);

	nyoci_outbound_append_content("Hello world!", NYOCI_CSTR_LEN);

	return nyoci_outbound_send();
}

nyoci_status_t
resend_handler(void* context)
{
	char* requestUrl = (char*)context;
	nyoci_status_t status = 0;

	status = nyoci_outbound_begin(
		nyoci_get_current_instance(),
		COAP_METHOD_GET,
		COAP_TRANS_TYPE_CONFIRMABLE
	);
	require_noerr(status,bail);

	nyoci_outbound_add_option_uint(COAP_OPTION_URI_PATH,0);
	nyoci_outbound_add_option_uint(COAP_OPTION_URI_PATH,0);
	nyoci_outbound_add_option_uint(COAP_OPTION_URI_PATH,0);

	status = nyoci_outbound_set_uri(requestUrl, 0);
	require_noerr(status,bail);

	status = nyoci_outbound_send();

	if(status) {
		check_noerr(status);
		fprintf(
			stderr,
			"nyoci_outbound_send() returned error %d(%s).\n",
			status,
			nyoci_status_to_cstr(status)
		);
		goto bail;
	}

bail:
	if(status == 0) {
		printf("Sent Request.\n");
	} else {
		if(status == NYOCI_STATUS_HOST_LOOKUP_FAILURE) {
			printf("Request Delayed: %d (%s)\n", status, nyoci_status_to_cstr(status));
			status = NYOCI_STATUS_WAIT_FOR_DNS;
		} else {
			printf("Request Failed: %d (%s)\n", status, nyoci_status_to_cstr(status));
			exit(EXIT_FAILURE);
		}
	}

	return status;
}

nyoci_status_t
response_handler(int statuscode, void* context)
{
	struct test_concurrency_thread_s* obj = (struct test_concurrency_thread_s*)context;
	gIsFinished = true;
	if (statuscode == NYOCI_STATUS_TRANSACTION_INVALIDATED) {
		printf("Transaction invalidated\n");
	} else if (statuscode == COAP_RESULT_205_CONTENT) {
		printf("Got content: %s\n", nyoci_inbound_get_content_ptr());
	} else if (statuscode == COAP_RESULT_404_NOT_FOUND) {
		printf("Resource not found\n");
	} else {
		printf("ERROR: Got unexpected status code %d (%s)\n", statuscode, nyoci_status_to_cstr(statuscode));
		exit(EXIT_FAILURE);
	}
	return 0;
}

int
main(void)
{
	nyoci_t instance;
	nyoci_node_t root_node;
	char *requestUrl = NULL;
	struct nyoci_transaction_s transaction;

	NYOCI_LIBRARY_VERSION_CHECK();

	// Create our instance on the default CoAP port. If the port
	// is already in use, we will pick the next available port number.
	instance = nyoci_create();

	if (!instance) {
		perror("Unable to create LibNyoci instance");
		exit(EXIT_FAILURE);
	}

	nyoci_plat_bind_to_port(instance, NYOCI_SESSION_TYPE_UDP, 0);

	printf("Listening on port %d\n",nyoci_plat_get_port(instance));

	root_node = nyoci_node_init(NULL, NULL, NULL);

	// LibNyoci will always respond to requests with METHOD_NOT_IMPLEMENTED
	// unless a request handler is set. Unless your program is only
	// making CoAP requests, you'll need a line like the following
	// in your program. The request handler may either handle the
	// request itself or route the request to the appropriate handler.
	// In this case, we are going to use the node router.
	nyoci_set_default_request_handler(instance, &nyoci_node_router_handler, (void*)root_node);

	nyoci_node_t hello_node = nyoci_node_init(NULL, root_node, "hello-world");
	hello_node->request_handler = &request_handler;
	hello_node->context = NULL;

	asprintf(&requestUrl, "coap://localhost:%d////hello-world////", nyoci_plat_get_port(instance));

	nyoci_transaction_init(
		&transaction,
		NYOCI_TRANSACTION_ALWAYS_INVALIDATE,
		&resend_handler,
		&response_handler,
		(void*)requestUrl
	);

	nyoci_transaction_begin(
		instance,
		&transaction,
		3*MSEC_PER_SEC
	);

	// Loop forever. This is the most simple kind of main loop you
	// can haave with LibNyoci. It is appropriate for simple CoAP servers
	// and clients which do not need asynchronous I/O.
	while (!gIsFinished) {
		nyoci_plat_wait(instance, CMS_DISTANT_FUTURE);
		nyoci_plat_process(instance);
	}

	// We won't actually get to this line with the above loop, but it
	// is always a good idea to clean up when you are done. If you
	// provide a way to gracefully exit from your own main loop, you
	// can tear down the LibNyoci instance using the following command.
	nyoci_release(instance);

	return EXIT_SUCCESS;
}
