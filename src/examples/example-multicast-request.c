/*!	@page nyoci-example-multicast-request example-multicast-request.c: Sending multicast request
**
**	This example shows how to send a (multicast) request and receive multiple responses.
**
**	@include example-multicast-request.c
**
*/

#include <libnyoci/libnyoci.h>
#include <libnyoci/nyoci-transaction.h>

typedef struct{
	const char * url;
	nyoci_transaction_t transaction;

	int consecutive_dups;
} transaction_context_t;

#define DEFAULT_TIMEOUT 10000 /* in milliseconds */
#define MAX_DUPS 5

nyoci_status_t
send_transaction_callback(void * context) {
	nyoci_status_t status;

	transaction_context_t * ctx = (transaction_context_t *)context;

	/*  A resend callback can return 'NYOCI_STATUS_STOP_RESENDING'
		to stop sending packets (the callback will not be called anymore)
		without invalidate the transaction.

		To illustrate this, this sample counts the number of consecutive
		duplicate responses and stop sending packets when it reaches a
		threshold.
	*/
	if(ctx->consecutive_dups > MAX_DUPS){
		printf("\nStop resending requests. Reached limit of consecutive duplicate responses.\n");
		return NYOCI_STATUS_STOP_RESENDING;
	}

	nyoci_t nyoci = nyoci_get_current_instance();

	printf("\nsend_transaction_callback(): Sending request\n");

	status = nyoci_outbound_begin(
		nyoci,
		COAP_METHOD_GET,
		COAP_TRANS_TYPE_NONCONFIRMABLE  //multicast requests should be non confirmable
	);

	if (status != NYOCI_STATUS_OK) {
		goto bail;
	}

	status = nyoci_outbound_set_uri(ctx->url, 0);

	if (status != NYOCI_STATUS_OK) {
		goto bail;
	}

	status = nyoci_outbound_send();

bail:
	return status;
}

nyoci_status_t
on_receive_response_callback(int statuscode, void * context)
{
	if (statuscode >= COAP_RESULT_100) {
		coap_size_t len = nyoci_inbound_get_content_len();
		const char * content = nyoci_inbound_get_content_ptr();

		printf("on_receive_response_callback(): statuscode=%d\n", statuscode);

		transaction_context_t * request = (transaction_context_t *)context;
		if (nyoci_inbound_is_dupe()) {
			printf(" --> Duplicate %d(%s) response\n", COAP_TO_HTTP_CODE(statuscode), coap_code_to_cstr(statuscode));
			request->consecutive_dups++;
		} else {
			printf(" --> Got %d(%s) response\n", COAP_TO_HTTP_CODE(statuscode), coap_code_to_cstr(statuscode));

			if (len > 0 && content != NULL) {
				printf("%.*s\n", len, content);
			}

			request->consecutive_dups=0;
		}
	}

	if (statuscode < NYOCI_STATUS_OK) {
		printf("on_receive_response_callback(): statuscode=%d (%s)\n", statuscode, nyoci_status_to_cstr(statuscode));

		/* Finish the transaction if got an error statuscode (ex: when timeout). */
		if (context != NULL) {
			transaction_context_t * ctx = (transaction_context_t *)context;

			nyoci_transaction_t transaction = ctx->transaction;

			printf(" --> Transaction complete\n");

			transaction->context = NULL;

			nyoci_transaction_end(nyoci_get_current_instance(), transaction);
		}
	}

	return NYOCI_STATUS_OK;
}

int
main(int argc, char ** argv)
{
	nyoci_t instance;
	nyoci_transaction_t transaction;
	char * url = argc > 1 ? argv[1] : "coap://[ff02::fd]/";
	transaction_context_t ctx = {url, NULL, 0};

	NYOCI_LIBRARY_VERSION_CHECK();

	instance = nyoci_create();

	if (!instance) {
		perror("Unable to create LibNyoci instance");
		exit(EXIT_FAILURE);
	}

	nyoci_plat_bind_to_port(instance, NYOCI_SESSION_TYPE_UDP, 0);

	/* Enable 'NYOCI_TRANSACTION_NO_AUTO_END' flag to receive responses
	 * from multiple servers.
	 *
	 * This flag prevents the request to be automatically finished after
	 * receiving the first response, but requires the transaction to be
	 * invalidated manually (see on_receive_response_callback below)
	 *
	 * `NYOCI_TRANSACTION_BURST_MULTICAST` causes a burst of packets
	 * to be sent instead of just a single packet for retransmit attempts.
	 * This can help make multicast POSTs take effect more simultaneously.
	 */

	transaction = nyoci_transaction_init(
		NULL,
		NYOCI_TRANSACTION_ALWAYS_INVALIDATE
		| NYOCI_TRANSACTION_NO_AUTO_END
		| NYOCI_TRANSACTION_BURST_MULTICAST,
		send_transaction_callback,
		on_receive_response_callback,
		&ctx
	);

	if (!transaction) {
		printf("Unable to create transaction\n");
		exit(EXIT_FAILURE);
	}

	ctx.transaction = transaction;

	nyoci_transaction_begin(instance, transaction, DEFAULT_TIMEOUT);

	/* Process messages and wait until request is done */
	do {
		nyoci_plat_wait(instance, CMS_DISTANT_FUTURE);
		nyoci_plat_process(instance);
	} while(ctx.transaction->active);

	nyoci_release(instance);

	return 0;
}
