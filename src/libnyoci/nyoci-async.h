/*!	@file nyoci-async.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
**	@brief Asynchronous Response Support
**
**	Copyright (C) 2017 Robert Quattlebaum
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

#ifndef NYOCI_nyoci_async_h
#define NYOCI_nyoci_async_h

#if !defined(NYOCI_INCLUDED_FROM_LIBNYOCI_H) && !defined(BUILDING_LIBNYOCI)
#error "Do not include this header directly, include <libnyoci/libnyoci.h> instead"
#endif

NYOCI_BEGIN_C_DECLS

/*!	@addtogroup nyoci
**	@{
*/

/*!	@defgroup nyoci_async Asynchronous response support API
**	@{
*/

//!	Don't immediately send an empty coap message.
/*!	Normally, when you call nyoci_outbound_begin_async_response(),
**	an empty message is sent to the requester to indicate
**	that they don't need to send any retries. This flag
**	tells the function to not attempt to send this empty message.
*/
#define NYOCI_ASYNC_RESPONSE_FLAG_DONT_ACK		(1<<0)

struct nyoci_async_response_s {
	nyoci_sockaddr_t sockaddr_local;
	nyoci_sockaddr_t sockaddr_remote;

	coap_size_t request_len;
	union {
		struct coap_header_s header;
		uint8_t bytes[NYOCI_ASYNC_RESPONSE_MAX_LENGTH];
	} request;
};

typedef struct nyoci_async_response_s* nyoci_async_response_t;

NYOCI_API_EXTERN bool nyoci_inbound_is_related_to_async_response(struct nyoci_async_response_s* x);

NYOCI_API_EXTERN nyoci_status_t nyoci_start_async_response(struct nyoci_async_response_s* x,int flags);

NYOCI_API_EXTERN nyoci_status_t nyoci_finish_async_response(struct nyoci_async_response_s* x);

NYOCI_API_EXTERN nyoci_status_t nyoci_outbound_begin_async_response(coap_code_t code, struct nyoci_async_response_s* x);

/*!	@} */


/*!	@} */

NYOCI_END_C_DECLS

#endif
