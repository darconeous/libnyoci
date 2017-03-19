/*!	@page nyoci-example-3 example-3.c: Using the node router
**
**	This example shows how to respond to a request for specific resources
**	using the node router.
**
**	@include example-3.c
**
**	## Results ##
**
**	    $ nyocictl
**	    Listening on port 61617.
**	    coap://localhost/> ls
**	    hello-world
**	    coap://localhost/> cat hello-world
**	    Hello world!
**	    coap://localhost/> cat hello-world -i
**	    CoAP/1.0 2.05 CONTENT tt=ACK(2) msgid=0xCBE1
**	    Token: CB E1
**	    Content-type: text/plain;charset=utf-8
**	    Payload-Size: 12
**
**	    Hello world!
**	    coap://localhost/>
**
**	@sa @ref nyoci-node-router
**
*/

#include <stdio.h>
#include <libnyoci/libnyoci.h>
#include <libnyociextra/nyoci-node-router.h>

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

int
main(void)
{
	nyoci_t instance;
	nyoci_node_t root_node;

	NYOCI_LIBRARY_VERSION_CHECK();

	// Create our instance on the default CoAP port. If the port
	// is already in use, we will pick the next available port number.
	instance = nyoci_create();

	if (!instance) {
		perror("Unable to create LibNyoci instance");
		exit(EXIT_FAILURE);
	}

	nyoci_plat_bind_to_port(instance, NYOCI_SESSION_TYPE_UDP, COAP_DEFAULT_PORT);

	// Join coap multicast groups
	nyoci_plat_join_standard_groups(instance, NYOCI_ANY_INTERFACE);

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

	printf("Listening on port %d\n", nyoci_plat_get_port(instance));

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
