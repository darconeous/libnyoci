/*
 *  cmd_list.c
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
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <libnyoci/libnyoci.h>
#include <string.h>
#include <sys/errno.h>
#include "help.h"
#include "cmd_list.h"
#include <string.h>
#include <libnyoci/url-helpers.h>
#include <math.h>
#include <signal.h>
#include "nyocictl.h"
#include <unistd.h>

static arg_list_item_t option_list[] = {
	{ 'h', "help",		 NULL,	 "Print Help"				 },
	{ 'i', "include",	 NULL,	 "Include headers in output" },
	{ 0,   "filename-only",	NULL, "Only print out the resulting filenames." },
	{ 't',   "timeout",	"cms", "Timeout value, in milliseconds" },
	{ 0 }
};

static coap_msg_id_t tid;
static uint16_t size_request;

static int gRet;
static sig_t previous_sigint_handler;
static void
signal_interrupt(int sig) {
	gRet = ERRORCODE_INTERRUPT;
	signal(SIGINT, previous_sigint_handler);
}

bool send_list_request(
	nyoci_t nyoci, const char* url, const char* next, coap_size_t nextlen);

static int retries = 0;
static const char* url_data;
static char next_data[256];
static coap_size_t next_len = ((coap_size_t)(-1));
static bool list_show_headers = false;
static int redirect_count = 0;
static char original_url[NYOCI_MAX_URI_LENGTH+1];
static int timeout_cms;
static bool list_filename_only;

static char redirect_url[NYOCI_MAX_URI_LENGTH + 1];

static char* list_data;
static coap_size_t list_data_size;
static struct nyoci_transaction_s transaction;

static void
parse_link_format(char* content, coap_size_t content_length, void* context) {
	char *iter = content;
	char *end = content + content_length;
	int col_width = 16;
	bool istty = isatty(fileno(stdout));

	while(iter && (iter < end)) {
		if(*iter == '<') {
			bool has_trailing_slash = false;
			char* uri = 0;
			char* name = 0;
			char* desc = 0;
			char* v = 0;
			char* sh_url = 0;
			coap_content_type_t type = COAP_CONTENT_TYPE_UNKNOWN;
			int uri_len = 0;

			iter++;

			uri = strsep(&iter, ">");
			//uri_len = iter - uri - 1;

			if(!iter)
				goto finished_parsing;

			// Skip past any arguments
			if(iter && *iter == ';') {
				while(iter && (iter < end)) {
					char* key;
					char* value;
					char endchar;

					iter++;
					key=iter;
					while(*iter && *iter!='=' && *iter!=';' && *iter!=',') {
						iter++;
					}

					if(*iter==';') {
						*iter = 0;
						continue;
					}

					if(!*iter || *iter==',')
						break;

					*iter++ = 0;

					if(*iter == '"') {
						iter++;
						value = iter;
						while(iter) {
							iter = strstr(iter,"\"");
							if(!iter || iter[-1]!='\\')
								break;
						}
						if(!iter)
							break;
						*iter++ = 0;
//								value = strsep(&iter, "\"");
//								if(!iter)
//									break;
						endchar = *iter++;
					} else {
						value = iter;
						while((iter < end) && (*iter != ',') &&
								(*iter != ';')) {
							iter++;
						}
						endchar = *iter;
						*iter++ = 0;
					}
					{	// Convert all line feeds into " | ".
						char* value_iter = value;
						for(;*value_iter;value_iter++) {
							if(0==strncmp(value_iter,"\n",1)) {
								if(value_iter[1]) {
									value_iter[0]='|';
								} else {
									value_iter[0]=0;
								}
							}
						}
					}
					// TODO: Unquote...?
					//url_decode_cstr_inplace(value);
					if(0 == strcmp(key, "n"))
						name = value;
					else if(!name && 0 == strcmp(key, "rt"))
						name = value;
					else if(0 == strcmp(key, "title"))
						desc = value;
					else if(0 == strcmp(key, "v"))
						v = value;
					else if(0 == strcmp(key, "ct"))
						type = (coap_content_type_t)strtol(value, NULL, 0);
					else if(0 == strcmp(key, "sh"))
						sh_url = value;
					//printf("%s = %s\n",key,value);
					if(endchar == ',' || (iter >= end))
						break;
					if(endchar == ';')
						iter--;
				}
			}

			char adjusted_uri[NYOCI_MAX_URI_LENGTH + 1];

			if(redirect_url[0] && !url_is_absolute(uri)) {
				strcpy(adjusted_uri, redirect_url);
				url_change(adjusted_uri, uri);
				uri = adjusted_uri;
			}
			url_shorten_reference((const char*)original_url, uri);

			// Strip the trailing slash.
			if(!strchr(uri,'?'))
			while(uri[0] && uri[strlen(uri)-1]=='/') {
				has_trailing_slash = true;
				uri[strlen(uri)-1] = 0;
			}

			if(istty && !list_filename_only && type==COAP_CONTENT_TYPE_APPLICATION_LINK_FORMAT)
				uri_len = fprintf(stdout,
					"\033[0;1;34m"
					"%s"
					"\033[0;37m"
					,
					uri
				) - 1;
			else
				uri_len = fprintf(stdout,"%s", uri) - 1;
			if(has_trailing_slash || type==COAP_CONTENT_TYPE_APPLICATION_LINK_FORMAT)
				fprintf(stdout,"/");
			if(!list_filename_only) {
				if(v)
					fprintf(stdout,"%s%s",istty?"\033[0;1m=\033[0m":"=",v);
				fprintf(stdout," ");
				if(uri_len < col_width) {
					if(name || (type != COAP_CONTENT_TYPE_UNKNOWN)) {
						uri_len = col_width - uri_len;
						while(uri_len--) {
							fprintf(stdout," ");
						}
						fprintf(stdout,"\t");
					}
				} else {
					fprintf(stdout,"\t");
					col_width = uri_len;
				}

				if(name && (0 != strcmp(name, uri))) fprintf(stdout,"\"%s\" ",
						name);
				if(sh_url && (0 != strcmp(sh_url, uri))) fprintf(stdout,
						"<%s> ",
						sh_url);
				if(type != COAP_CONTENT_TYPE_UNKNOWN) fprintf(stdout,"[%s] ",
						coap_content_type_to_cstr(type));
				if(desc) fprintf(stdout,"(%s) ",desc);
			}
			fprintf(stdout,"\n");
		} else {
			iter++;
		}
	}
finished_parsing:
	return;
}


static nyoci_status_t
list_response_handler(
	int statuscode, void* context
) {
//	nyoci_t const self = nyoci_get_current_instance();
	char* content = (char*)nyoci_inbound_get_content_ptr();
	coap_size_t content_length = nyoci_inbound_get_content_len();

	if(statuscode == NYOCI_STATUS_TRANSACTION_INVALIDATED) {
		if(list_data && list_data_size)
			parse_link_format(list_data,list_data_size,context);
		gRet = 0;
		return NYOCI_STATUS_TRANSACTION_INVALIDATED;
	}

	if(statuscode>=0) {
		if(content_length>(nyoci_inbound_get_packet_length()-4)) {
			fprintf(stderr, "INTERNAL ERROR: CONTENT_LENGTH LARGER THAN PACKET_LENGTH-4! (content_length=%u, packet_length=%u)\n",content_length,nyoci_inbound_get_packet_length());
			gRet = ERRORCODE_UNKNOWN;
			goto bail;
		}

		if(list_show_headers) {
			if(next_len != ((coap_size_t)(-1)))
				fprintf(stdout, "\n");
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


	if(((statuscode < COAP_RESULT_200) ||
				(statuscode >= COAP_RESULT_400)) &&
			(statuscode != NYOCI_STATUS_TRANSACTION_INVALIDATED) &&
			(statuscode != HTTP_TO_COAP_CODE(HTTP_RESULT_CODE_PARTIAL_CONTENT))
	) {
		if(!list_filename_only) {
			fprintf(stderr, "list: Result code = %d (%s)\n", statuscode,
					(statuscode < 0) ? nyoci_status_to_cstr(
					statuscode) : coap_code_to_cstr(statuscode));
		}
		if(statuscode<0)
			gRet = statuscode;
		else if(content_length && !list_filename_only) {
			fprintf(stdout,"%s",content);
			if((content[content_length - 1] != '\n'))
				fprintf(stdout,"\n");
		}
		goto bail;
	}

	// TODO: When redirected, we should adjust the URI's to be relative to the original url!

	if(content && content_length) {
		coap_content_type_t content_type = nyoci_inbound_get_content_type();

		if(content_type != COAP_CONTENT_TYPE_APPLICATION_LINK_FORMAT && content_type != COAP_CONTENT_TYPE_UNKNOWN) {
			if(!list_filename_only) {
				if(statuscode >= COAP_RESULT_300) {
					fwrite(content, content_length, 1, stdout);
					if((content[content_length - 1] != '\n'))
						fprintf(stdout,"\n");
				} else {
					fprintf(stderr, " *** Not a directory (content type is '%s')\n",coap_content_type_to_cstr(content_type));
					gRet = 0;
					return NYOCI_STATUS_TRANSACTION_INVALIDATED;
				}
			}
		} else {
			list_data_size += content_length;
			list_data = realloc(list_data,list_data_size);
			if(list_data) {
				memcpy(list_data+list_data_size-content_length,content,content_length);
			}
			//parse_link_format(content,content_length,context);

			return NYOCI_STATUS_OK;
		}
	}
bail:
//	if(gRet == ERRORCODE_INPROGRESS)
//		gRet = 0;
	return NYOCI_STATUS_OK;
}

static nyoci_status_t
resend_list_request(void* context) {
	nyoci_status_t status = 0;

	status = nyoci_outbound_begin(nyoci_get_current_instance(),COAP_METHOD_GET, COAP_TRANS_TYPE_CONFIRMABLE);
	require_noerr(status,bail);

	status = nyoci_outbound_set_uri(url_data, 0);
	require_noerr(status,bail);

	status = nyoci_outbound_add_option_uint(COAP_OPTION_ACCEPT,COAP_CONTENT_TYPE_APPLICATION_LINK_FORMAT);
	require_noerr(status,bail);

//	if(next_len != ((coap_size_t)(-1))) {
//		status = nyoci_outbound_add_option(
//			COAP_OPTION_BLOCK2,
//			next_data,
//			next_len
//		);
//		require_noerr(status,bail);
//	}

//	if(size_request) {
//		nyoci_outbound_add_option(
//			COAP_OPTION_SIZE_REQUEST,
//			(void*)&size_request,
//			sizeof(size_request)
//		);
//		require_noerr(status,bail);
//	}

	status = nyoci_outbound_send();

	if(status) {
		check_noerr(status);
		fprintf(stderr,
			"nyoci_outbound_send() returned error %d(%s).\n",
			status,
			nyoci_status_to_cstr(status));
		goto bail;
	}

bail:
	return status;
}

bool
send_list_request(
	nyoci_t nyoci, const char* url, const char* next, coap_size_t nextlen
) {
	bool ret = false;
	nyoci_status_t status = 0;
	int flags = NYOCI_TRANSACTION_ALWAYS_INVALIDATE;
	tid = nyoci_get_next_msg_id(nyoci);
	gRet = ERRORCODE_INPROGRESS;

	retries = 0;
	url_data = url;
	if(next) {
		memcpy(next_data, next, nextlen);
		next_len = nextlen;
	} else {
		next_len = ((coap_size_t)(-1));
	}

	nyoci_transaction_end(nyoci,&transaction);
	nyoci_transaction_init(
		&transaction,
		flags, // Flags
		(void*)&resend_list_request,
		(void*)&list_response_handler,
		(void*)url_data
	);
	status = nyoci_transaction_begin(nyoci, &transaction, timeout_cms);

	tid = transaction.msg_id;

	if(status) {
		check(!status);
		fprintf(stderr,
			"nyoci_begin_transaction_old() returned %d(%s).\n",
			status,
			nyoci_status_to_cstr(status));
		goto bail;
	}

	ret = true;

bail:
	return ret;
}

int
tool_cmd_list(
	nyoci_t nyoci, int argc, char* argv[]
) {
	int i;
	char url[NYOCI_MAX_URI_LENGTH+1];

	gRet = ERRORCODE_INPROGRESS;
	previous_sigint_handler = signal(SIGINT, &signal_interrupt);
	next_len = ((coap_size_t)(-1));
	url[0] = 0;
	list_show_headers = false;
	redirect_count = 10;
	redirect_url[0] = 0;
	size_request = 0;
	list_data_size = 0;

	timeout_cms = 30*1000;
	list_filename_only = false;

	BEGIN_LONG_ARGUMENTS(gRet)
	HANDLE_LONG_ARGUMENT("include") list_show_headers = true;
	HANDLE_LONG_ARGUMENT("no-follow") redirect_count = 0;
	HANDLE_LONG_ARGUMENT("follow") redirect_count = 10;
	HANDLE_LONG_ARGUMENT("slice-size") size_request =
		htons(strtol(argv[++i], NULL, 0));
	HANDLE_LONG_ARGUMENT("timeout") timeout_cms = (int)strtol(argv[++i], NULL, 0);
	HANDLE_LONG_ARGUMENT("filename-only") list_filename_only = true;

	HANDLE_LONG_ARGUMENT("help") {
		print_arg_list_help(option_list, argv[0], "[args] <uri>");
		gRet = ERRORCODE_HELP;
		goto bail;
	}
	BEGIN_SHORT_ARGUMENTS(gRet)
	HANDLE_SHORT_ARGUMENT('i') list_show_headers = true;
	HANDLE_SHORT_ARGUMENT('f') redirect_count = 10;
	HANDLE_SHORT_ARGUMENT('t') timeout_cms = (int)strtol(argv[++i], NULL, 0);

	HANDLE_SHORT_ARGUMENT2('h', '?') {
		print_arg_list_help(option_list, argv[0], "[args] <uri>");
		gRet = ERRORCODE_HELP;
		goto bail;
	}
	HANDLE_OTHER_ARGUMENT() {
		if(url[0] == 0) {
			if(getenv("NYOCI_CURRENT_PATH")) {
				strncpy(url, getenv("NYOCI_CURRENT_PATH"), sizeof(url));
				url_change(url, argv[i]);
				//if(url[0] && '/'!=url[strlen(url)-1] && !strchr(url,'?')) {
				//	strcat(url,"/");
				//}
			} else {
				strncpy(url, argv[i], sizeof(url));
			}
		} else {
			fprintf(stderr, "Unexpected extra argument: \"%s\"\n", argv[i]);
			gRet = ERRORCODE_BADARG;
			goto bail;
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

	strncpy(original_url,url,NYOCI_MAX_URI_LENGTH);

	// Remove query component.
	// TODO: Why?
	if(strchr(original_url,'?')) {
		strchr(original_url,'?')[0] = 0;
	}

	require(send_list_request(nyoci, url, NULL, 0), bail);

	while(ERRORCODE_INPROGRESS == gRet) {
		nyoci_plat_wait(nyoci,1000);
		nyoci_plat_process(nyoci);
	}

bail:
	nyoci_transaction_end(nyoci,&transaction);
	signal(SIGINT, previous_sigint_handler);
	url_data = NULL;
	return gRet;
}
