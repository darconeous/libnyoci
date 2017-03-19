/*	@file nyoci-simple.c
**	@author Robert Quattlebaum <darco@deepdarc.com>
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

#include "nyoci-task.h"
#include "net/ip/resolv.h"
#include <libnyoci/libnyoci.h>

PROCESS_NAME(nyoci_simple);
PROCESS(nyoci_simple, "LibNyoci Simple Demo");

/*---------------------------------------------------------------------------*/
AUTOSTART_PROCESSES(
	&resolv_process,
	&nyoci_task,
	&nyoci_simple,
	NULL
);

/*---------------------------------------------------------------------------*/
static nyoci_status_t
request_handler(void* context) {
	/*	This will respond to every GET request to `/hello-world' with
	**	"Hello world!". Everyone else gets a 4.04 Not Found. */

	printf("Got a request!\n");

	if(nyoci_inbound_get_code() != COAP_METHOD_GET) {
		return NYOCI_STATUS_NOT_IMPLEMENTED;
	}

	while(nyoci_inbound_peek_option(NULL, NULL) != COAP_OPTION_URI_PATH)
		if(nyoci_inbound_next_option(NULL, NULL) == COAP_OPTION_INVALID)
			break;

	if(nyoci_inbound_option_strequal(COAP_OPTION_URI_PATH, "hello-world")) {

		nyoci_outbound_begin_response(COAP_RESULT_205_CONTENT);

		nyoci_outbound_add_option_uint(
			COAP_OPTION_CONTENT_TYPE,
			COAP_CONTENT_TYPE_TEXT_PLAIN
		);

		nyoci_outbound_append_content("Hello world!", NYOCI_CSTR_LEN);

		return nyoci_outbound_send();
	} else if(nyoci_inbound_option_strequal(COAP_OPTION_URI_PATH, ".well-known")) {
		nyoci_inbound_next_option(NULL, NULL);

		if(nyoci_inbound_option_strequal(COAP_OPTION_URI_PATH, "core")) {
			nyoci_outbound_begin_response(COAP_RESULT_205_CONTENT);

			nyoci_outbound_add_option_uint(
				COAP_OPTION_CONTENT_TYPE,
				COAP_CONTENT_TYPE_APPLICATION_LINK_FORMAT
			);

			nyoci_outbound_append_content("</hello-world>", NYOCI_CSTR_LEN);

			return nyoci_outbound_send();
		}
	}

	return NYOCI_STATUS_NOT_FOUND;
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(nyoci_simple, ev, data)
{
	PROCESS_BEGIN();

	nyoci_set_default_request_handler(instance, &request_handler, NULL);

	PROCESS_END();
}
