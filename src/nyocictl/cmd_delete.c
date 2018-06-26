/*
 *  cmd_delete.c
 *  LibNyoci
 *
 *  Created by Robert Quattlebaum on 8/17/10.
 *  Copyright 2010 deepdarc. All rights reserved.
 *
 */

/* This file is a total mess and needs to be cleaned up! */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include "assert-macros.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <libnyoci/libnyoci.h>
#include <string.h>
#include <sys/errno.h>
#include "help.h"
#include "cmd_delete.h"
#include <libnyoci/url-helpers.h>
#include <signal.h>
#include "nyocictl.h"

/*
   static arg_list_item_t option_list[] = {
	{ 'h', "help",NULL,"Print Help" },
	{ 0 }
   };
 */

static int gRet;
static sig_t previous_sigint_handler;
static bool delete_show_headers;

/*
   static arg_list_item_t option_list[] = {
	{ 'h', "help",NULL,"Print Help" },
	{ 'c', "content-file",NULL,"Use content from the specified input source" },
	{ 0 }
   };
 */
static void
signal_interrupt(int sig) {
	gRet = ERRORCODE_INTERRUPT;
	signal(SIGINT, previous_sigint_handler);
}

static nyoci_status_t
delete_response_handler(
	int			statuscode,
	void*		context
) {
	if (statuscode >= 0) {
		char* content = (char*)nyoci_inbound_get_content_ptr();
		coap_size_t content_length = nyoci_inbound_get_content_len();

		if(content_length>(nyoci_inbound_get_packet_length()-4)) {
			fprintf(stderr, "INTERNAL ERROR: CONTENT_LENGTH LARGER THAN PACKET_LENGTH-4! (content_length=%u, packet_length=%u)\n",content_length,nyoci_inbound_get_packet_length());
			gRet = ERRORCODE_UNKNOWN;
			goto bail;
		}

		if (delete_show_headers) {
			coap_dump_header(
				stdout,
				NULL,
				nyoci_inbound_get_packet(),
				nyoci_inbound_get_packet_length()
			);
		}

		if(!coap_verify_packet((void*)nyoci_inbound_get_packet(), nyoci_inbound_get_packet_length())) {
			fprintf(stderr, "INTERNAL ERROR: CALLBACK GIVEN INVALID PACKET!\n");
			gRet = ERRORCODE_UNKNOWN;
			goto bail;
		}


		if (statuscode != COAP_RESULT_202_DELETED) {
			fprintf(stderr, "delete: Result code = %d (%s)\n", statuscode,
					(statuscode < 0) ? nyoci_status_to_cstr(
					statuscode) : coap_code_to_cstr(statuscode));
		}

		if(content && content_length) {
			char contentBuffer[500];

			content_length =
				((content_length > sizeof(contentBuffer) -
					2) ? sizeof(contentBuffer) - 2 : content_length);
			memcpy(contentBuffer, content, content_length);
			contentBuffer[content_length] = 0;

			if(content_length && (contentBuffer[content_length - 1] == '\n'))
				contentBuffer[--content_length] = 0;

			printf("%s\n", contentBuffer);
		}
	}

bail:
	if (gRet == ERRORCODE_INPROGRESS) {
		gRet = 0;
	}
	return NYOCI_STATUS_OK;
}

static nyoci_status_t
resend_delete_request(const char* url) {
	nyoci_status_t status = 0;

	status = nyoci_outbound_begin(nyoci_get_current_instance(), COAP_METHOD_DELETE, COAP_TRANS_TYPE_CONFIRMABLE);
	require_noerr(status,bail);

	status = nyoci_outbound_set_uri(url, 0);
	require_noerr(status,bail);

	status = nyoci_outbound_send();
	require_noerr(status,bail);

	gRet = ERRORCODE_INPROGRESS;

bail:
	return status;
}


static nyoci_transaction_t
send_delete_request(
	nyoci_t nyoci, const char* url
) {
	nyoci_transaction_t ret;

	gRet = ERRORCODE_INPROGRESS;

	ret = nyoci_transaction_init(
		NULL,
		NYOCI_TRANSACTION_ALWAYS_INVALIDATE, // Flags
		(void*)&resend_delete_request,
		&delete_response_handler,
		(void*)url
	);
	nyoci_transaction_begin(nyoci, ret, 30*MSEC_PER_SEC);

bail:
	return ret;
}

int
tool_cmd_delete(
	nyoci_t nyoci, int argc, char* argv[]
) {
	previous_sigint_handler = signal(SIGINT, &signal_interrupt);
	nyoci_transaction_t transaction;

	char url[1000] = "";

	if((2 == argc) && (0 == strcmp(argv[1], "--help"))) {
		printf("Help not yet implemented for this command.\n");
		return ERRORCODE_HELP;
	}

	gRet = ERRORCODE_UNKNOWN;

	if (getenv("NYOCI_CURRENT_PATH")) {
		strncpy(url, getenv("NYOCI_CURRENT_PATH"), sizeof(url));
	}

	if (argc == 2) {
		url_change(url, argv[1]);
	} else {
		fprintf(stderr, "Bad args.\n");
		gRet = ERRORCODE_BADARG;
		goto bail;
	}

	require((transaction=send_delete_request(nyoci, url)), bail);

	gRet = ERRORCODE_INPROGRESS;

	while(ERRORCODE_INPROGRESS == gRet) {
		nyoci_plat_wait(nyoci, 1000);
		nyoci_plat_process(nyoci);
	}

	nyoci_transaction_end(nyoci, transaction);

bail:
	signal(SIGINT, previous_sigint_handler);
	return gRet;
}
