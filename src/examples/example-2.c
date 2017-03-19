/*!	@page nyoci-example-2 example-2.c: Responding to a specific request
**
**	This example shows how to respond to a request for a specific resource.
**
**	@include example-2.c
**
**	@sa @ref nyoci-instance, @ref nyoci-inbound, @ref nyoci-outbound
*/

#include <stdio.h>
#include <libnyoci/libnyoci.h>

static nyoci_status_t
request_handler(void* context)
{
	/*	This will respond to every GET request to `/hello-world' with
	**	"Hello world!". Everyone else gets a 4.04 Not Found. */

	printf("Got a request!\n");

	// Only handle GET requests for now. Returning NYOCI_STATUS_NOT_IMPLEMENTED
	// here without sending a response will cause us to automatically
	// send a METHOD_NOT_IMPLEMENTED response.
	if (nyoci_inbound_get_code() != COAP_METHOD_GET) {
		return NYOCI_STATUS_NOT_IMPLEMENTED;
	}

	// Skip to the URI path option
	while (nyoci_inbound_peek_option(NULL, NULL) != COAP_OPTION_URI_PATH) {
		if (nyoci_inbound_next_option(NULL, NULL) == COAP_OPTION_INVALID) {
			break;
		}
	}

	// If our URI path matches what we are looking for...
	if (nyoci_inbound_option_strequal(COAP_OPTION_URI_PATH, "hello-world")) {

		// Begin describing the response message. (2.05 CONTENT,
		// in this case)
		nyoci_outbound_begin_response(COAP_RESULT_205_CONTENT);

		// Add an option describing the content type as plaintext.
		nyoci_outbound_add_option_uint(
			COAP_OPTION_CONTENT_TYPE,
			COAP_CONTENT_TYPE_TEXT_PLAIN
		);

		// Set the content of our response to be "Hello world!".
		nyoci_outbound_append_content("Hello world!", NYOCI_CSTR_LEN);

		// Send the response we hae created, passing the return value
		// to our caller.
		return nyoci_outbound_send();
	}

	return NYOCI_STATUS_NOT_FOUND;
}

int
main(void)
{
	nyoci_t instance;

	NYOCI_LIBRARY_VERSION_CHECK();

	// Create our instance on the default CoAP port. If the port
	// is already in use, we will pick the next available port number.
	instance = nyoci_create();

	if (!instance) {
		perror("Unable to create LibNyoci instance");
		exit(EXIT_FAILURE);
	}

	nyoci_plat_bind_to_port(instance, NYOCI_SESSION_TYPE_UDP, COAP_DEFAULT_PORT);

	printf("Listening on port %d\n",nyoci_plat_get_port(instance));

	// LibNyoci will always respond to requests with METHOD_NOT_IMPLEMENTED
	// unless a request handler is set. Unless your program is only
	// making CoAP requests, you'll need a line like the following
	// in your program. The request handler may either handle the
	// request itself or route the request to the appropriate handler.
	nyoci_set_default_request_handler(instance, &request_handler, NULL);

	// Loop forever. This is the most simple kind of main loop you
	// can haave with LibNyoci. It is appropriate for simple CoAP servers
	// and clients which do not need asynchronous I/O.
	while (1) {
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
