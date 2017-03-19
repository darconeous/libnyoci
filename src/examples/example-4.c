/*!	@page nyoci-example-4 example-4.c: Making observable resources
**
**	This example shows how to make resources observable.
**
**	@include example-4.c
**
**	## Results ##
**
**	    $ nyocictl
**	    Listening on port 61617.
**	    coap://localhost/> ls
**	    hello-world
**	    coap://localhost/> obs -i hello-world
**	    CoAP/1.0 2.05 CONTENT tt=ACK(2) msgid=0x1E80
**	    Token: 1E 80
**	    Observe: 0
**	    Content-type: text/plain;charset=utf-8
**	    Payload-Size: 12
**
**	    Hello world!
**
**	    CoAP/1.0 2.05 CONTENT tt=NON(1) msgid=0x0961
**	    Token: 1E 80
**	    Observe: 1
**	    Content-type: text/plain;charset=utf-8
**	    Payload-Size: 12
**
**	    Hello world!
**
**	    CoAP/1.0 2.05 CONTENT tt=NON(1) msgid=0x0A61
**	    Token: 1E 80
**	    Observe: 2
**	    Content-type: text/plain;charset=utf-8
**	    Payload-Size: 12
**
**	    Hello world!
**
**	    ^Ccoap://localhost/>
**
**
**	@sa @ref nyoci-observable
*/

#include <stdio.h>
#include <time.h>

#include <libnyoci/libnyoci.h>
#include <libnyociextra/nyoci-node-router.h>

#define ARBITRARY_OBSERVABLE_KEY			23
#define TRIGGER_FREQUENCY					5		// In Seconds

static nyoci_status_t
request_handler(void* context)
{
	nyoci_observable_t observable = context;

	if (!nyoci_inbound_is_fake()) {
		printf("Got a request!\n");
	}

	// Only handle GET requests for now.
	if (nyoci_inbound_get_code() != COAP_METHOD_GET) {
		return NYOCI_STATUS_NOT_IMPLEMENTED;
	}

	// Begin describing the response.
	nyoci_outbound_begin_response(COAP_RESULT_205_CONTENT);

	// This is the key line to making a resource observable.
	// It must be placed after nyoci_outbound_begin_response()
	// and before nyoci_outbound_send(). When this resource changes,
	// a simple call to nyoci_observable_trigger() with the given
	// nyoci_observable object and observable key will trigger the
	// observers to be updated. Really --- that's it...!
	nyoci_observable_update(observable, ARBITRARY_OBSERVABLE_KEY);

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
	struct nyoci_observable_s observable = { 0 };
	time_t next_trigger;

	NYOCI_LIBRARY_VERSION_CHECK();

	instance = nyoci_create();

	if (!instance) {
		perror("Unable to create LibNyoci instance");
		exit(EXIT_FAILURE);
	}

	nyoci_plat_bind_to_port(instance, NYOCI_SESSION_TYPE_UDP, COAP_DEFAULT_PORT);

	root_node = nyoci_node_init(NULL, NULL, NULL);

	next_trigger = time(NULL) + TRIGGER_FREQUENCY;

	nyoci_set_default_request_handler(
		instance,
		&nyoci_node_router_handler,
		(void*)root_node
	);

	nyoci_node_t hello_node = nyoci_node_init(NULL,root_node,"hello-world");
	hello_node->request_handler = &request_handler;
	hello_node->context = &observable;

	printf("Listening on port %d\n", nyoci_plat_get_port(instance));

	while (1) {
		nyoci_plat_wait(instance, (next_trigger - time(NULL)) * MSEC_PER_SEC);
		nyoci_plat_process(instance);

		// Occasionally trigger this resource as having changed.
		if ((next_trigger - time(NULL))<=0) {
			printf("%d observers registered\n", nyoci_observable_observer_count(&observable, ARBITRARY_OBSERVABLE_KEY));
			nyoci_observable_trigger(&observable, ARBITRARY_OBSERVABLE_KEY ,0);
			next_trigger = time(NULL) + TRIGGER_FREQUENCY;
		}
	}

	nyoci_release(instance);

	return EXIT_SUCCESS;
}
