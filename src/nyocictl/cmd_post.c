/*
 *  cmd_post.c
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
#include <stdint.h>
#include <libnyoci/nyoci-helpers.h>
#include <libnyoci/nyoci-missing.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <libnyoci/libnyoci.h>
#include <string.h>
#include <sys/errno.h>
#include "help.h"
#include "cmd_post.h"
#include <libnyoci/url-helpers.h>
#include <signal.h>
#include "nyocictl.h"
#include "string-utils.h"

static arg_list_item_t option_list[] = {
	{ 'h', "help",				  NULL, "Print Help" },
	{ 'i', "include",	 NULL,	 "Include headers in output" },
	{ 0, "non",  NULL, "Send as non-confirmable" },
//	{ 'c', "content-file",NULL,"Use content from the specified input source" },
//	{ 0,   "outbound-slice-size", NULL, "writeme"	 },
	{ 0,   "content-type",		  "content-format", "Set content-format option"	 },
	{ 0 }
};

static int gRet;
static sig_t previous_sigint_handler;
static int outbound_slice_size;
static bool post_show_headers;
static coap_transaction_type_t post_tt;

static void
signal_interrupt(int sig) {
	gRet = ERRORCODE_INTERRUPT;
	signal(SIGINT, previous_sigint_handler);
}

struct post_request_s {
	char* url;
	char* content;
	coap_size_t content_len;
	coap_content_type_t content_type;
	coap_code_t method;
};


static nyoci_status_t
post_response_handler(
	int			statuscode,
	struct post_request_s *request
) {
	char* content = (char*)nyoci_inbound_get_content_ptr();
	coap_size_t content_length = nyoci_inbound_get_content_len();

	if(statuscode>=0) {
		if(content_length>(nyoci_inbound_get_packet_length()-4)) {
			fprintf(stderr, "INTERNAL ERROR: CONTENT_LENGTH LARGER THAN PACKET_LENGTH-4! (content_length=%u, packet_length=%u)\n",content_length,nyoci_inbound_get_packet_length());
			gRet = ERRORCODE_UNKNOWN;
			goto bail;
		}

		if((statuscode >= 0) && post_show_headers) {
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
	}

	if ( content != NULL
	  && (statuscode > 0)
	) {
		printf("%*s", content_length, content);
		// Only print a newline if the content doesn't already print one.
		if((content[content_length - 1] != '\n')) {
			printf("\n");
		}
	}

	if ( !content_length
	  && (statuscode != COAP_RESULT_204_CHANGED)
	  && (statuscode != NYOCI_STATUS_TRANSACTION_INVALIDATED)
	) {
		fprintf(stderr, "post: Result code = %d (%s)\n", statuscode,
				(statuscode < 0) ? nyoci_status_to_cstr(
				statuscode) : coap_code_to_cstr(statuscode));
	}

bail:
	if (gRet == ERRORCODE_INPROGRESS) {
		gRet = 0;
	}

	if (statuscode == NYOCI_STATUS_TRANSACTION_INVALIDATED) {
		free(request->content);
		free(request->url);
		free(request);
	}
	return NYOCI_STATUS_OK;
}


static nyoci_status_t
resend_post_request(struct post_request_s *request) {
	nyoci_status_t status = 0;

	status = nyoci_outbound_begin(nyoci_get_current_instance(),request->method, post_tt);
	require_noerr(status, bail);

	status = nyoci_outbound_add_option_uint(COAP_OPTION_CONTENT_TYPE, request->content_type);
	require_noerr(status, bail);

	status = nyoci_outbound_set_uri(request->url, 0);
	require_noerr(status, bail);

	status = nyoci_outbound_append_content(request->content, request->content_len);
	require_noerr(status, bail);

	status = nyoci_outbound_send();
	require_noerr(status, bail);

	switch (status) {
		case NYOCI_STATUS_OK:
		case NYOCI_STATUS_WAIT_FOR_SESSION:
		case NYOCI_STATUS_WAIT_FOR_DNS:
			break;
		default:
			check_noerr(status);
			fprintf(stderr,
				"nyoci_outbound_send() returned error %d(%s).\n",
				status,
				nyoci_status_to_cstr(status));
			break;
	}

bail:
	return status;
}

static nyoci_transaction_t
send_post_request(
	nyoci_t	nyoci,
	const char*		url,
	coap_code_t		method,
	const char*		content,
	coap_size_t		content_len,
	coap_content_type_t content_type
) {
	nyoci_transaction_t ret = NULL;
	struct post_request_s *request;

	request = calloc(1,sizeof(*request));
	require(request!=NULL,bail);
	request->url = strdup(url);
	request->content = calloc(1,content_len);
	memcpy(request->content,content,content_len);
	request->content_len = content_len;
	request->content_type = content_type;
	request->method = method;

	gRet = ERRORCODE_INPROGRESS;

	ret = nyoci_transaction_init(
		NULL,
		NYOCI_TRANSACTION_ALWAYS_INVALIDATE, // Flags
		(void*)&resend_post_request,
		(void*)&post_response_handler,
		(void*)request
	);
	nyoci_transaction_begin(nyoci, ret, 30*MSEC_PER_SEC);

bail:
	return ret;
}

int
tool_cmd_post(
	nyoci_t nyoci, int argc, char* argv[]
) {
	previous_sigint_handler = signal(SIGINT, &signal_interrupt);
	coap_content_type_t content_type = 0;
	coap_code_t method = COAP_METHOD_POST;
	nyoci_transaction_t transaction;
	int i;
	char url[1000];
	url[0] = 0;
	char content[10000];
	content[0] = 0;
	content_type = 0;
	if(strequal_const(argv[0],"put")) {
		method = COAP_METHOD_PUT;
	}
	outbound_slice_size = 100;
	post_show_headers = false;
	post_tt = COAP_TRANS_TYPE_CONFIRMABLE;

	BEGIN_LONG_ARGUMENTS(gRet)
	HANDLE_LONG_ARGUMENT("include") post_show_headers = true;
	HANDLE_LONG_ARGUMENT("outbound-slice-size") outbound_slice_size = (int)strtol(argv[++i], NULL, 0);
	HANDLE_LONG_ARGUMENT("content-type") content_type = coap_content_type_from_cstr(argv[++i]);
	HANDLE_LONG_ARGUMENT("content-format") content_type = coap_content_type_from_cstr(argv[++i]);
	HANDLE_LONG_ARGUMENT("non") post_tt = COAP_TRANS_TYPE_NONCONFIRMABLE;
	HANDLE_LONG_ARGUMENT("help") {
		print_arg_list_help(option_list,
			argv[0],
			"[args] <uri> <POST-Data>");
		gRet = ERRORCODE_HELP;
		goto bail;
	}
	BEGIN_SHORT_ARGUMENTS(gRet)
	HANDLE_SHORT_ARGUMENT('i') post_show_headers = true;
	HANDLE_SHORT_ARGUMENT2('h', '?') {
		print_arg_list_help(option_list,
			argv[0],
			"[args] <uri> <POST-Data>");
		gRet = ERRORCODE_HELP;
		goto bail;
	}
	HANDLE_OTHER_ARGUMENT() {
		if(url[0] == 0) {
			if(getenv("NYOCI_CURRENT_PATH")) {
				strncpy(url, getenv("NYOCI_CURRENT_PATH"), sizeof(url));
				url_change(url, argv[i]);
			} else {
				strncpy(url, argv[i], sizeof(url));
			}
		} else {
			if(content[0] == 0) {
				strncpy(content, argv[i], sizeof(content));
			} else {
				strlcat(content, " ", sizeof(content));
				strlcat(content, argv[i], sizeof(content));
			}
		}
	}
	END_ARGUMENTS

	if((url[0] == 0) && getenv("NYOCI_CURRENT_PATH"))
		strncpy(url, getenv("NYOCI_CURRENT_PATH"), sizeof(url));

	if(url[0] == 0) {
		fprintf(stderr, "Missing path argument.\n");
		gRet = ERRORCODE_BADARG;
		goto bail;
	}


	gRet = ERRORCODE_INPROGRESS;

	transaction = send_post_request(nyoci, url, method,content, (coap_size_t)strlen(content),content_type);

	while(ERRORCODE_INPROGRESS == gRet) {
		nyoci_plat_wait(nyoci,1000);
		nyoci_plat_process(nyoci);
	}

	nyoci_transaction_end(nyoci, transaction);

bail:
	signal(SIGINT, previous_sigint_handler);
	return gRet;
}
