/*!	@file nyoci-async.c
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

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include "assert-macros.h"
#include "libnyoci.h"
#include "nyoci-internal.h"
#include "nyoci-logging.h"

nyoci_status_t
nyoci_outbound_begin_async_response(coap_code_t code, struct nyoci_async_response_s* x) {
	nyoci_status_t ret = 0;
	nyoci_t const self = nyoci_get_current_instance();

	assert(NULL != x);

	self->inbound.packet = &x->request.header;
	self->inbound.packet_len = x->request_len;
	self->inbound.content_ptr = (char*)x->request.header.token + x->request.header.token_len;
	self->inbound.last_option_key = 0;
	self->inbound.this_option = x->request.header.token;
	self->inbound.flags |= NYOCI_INBOUND_FLAG_FAKE;
	nyoci_plat_set_remote_sockaddr(&x->sockaddr_remote);
	nyoci_plat_set_local_sockaddr(&x->sockaddr_local);

	self->is_processing_message = true;
	self->did_respond = false;

	ret = nyoci_outbound_begin_response(code);
	require_noerr(ret, bail);

	self->outbound.packet->msg_id = self->current_transaction->msg_id;

	self->outbound.packet->tt = x->request.header.tt;

	ret = nyoci_outbound_set_token(x->request.header.token, x->request.header.token_len);
	require_noerr(ret, bail);

	assert(coap_verify_packet((const char*)x->request.bytes, x->request_len));
bail:
	return ret;
}

nyoci_status_t
nyoci_start_async_response(struct nyoci_async_response_s* x, int flags) {
	nyoci_status_t ret = 0;
	nyoci_t const self = nyoci_get_current_instance();

	require_action_string(x!=NULL,bail,ret=NYOCI_STATUS_INVALID_ARGUMENT,"NULL async_response arg");

	require_action_string(
		nyoci_inbound_get_packet_length()-nyoci_inbound_get_content_len()<=sizeof(x->request),
		bail,
		(nyoci_outbound_quick_response(COAP_RESULT_413_REQUEST_ENTITY_TOO_LARGE,NULL),ret=NYOCI_STATUS_FAILURE),
		"Request too big for async response"
	);

	x->request_len = nyoci_inbound_get_packet_length()-nyoci_inbound_get_content_len();

	check(x->request_len <= sizeof(x->request));

	if (x->request_len > sizeof(x->request)) {
		x->request_len = sizeof(x->request);
		require_action(coap_verify_packet((const char*)x->request.bytes, x->request_len), bail, ret = NYOCI_STATUS_MESSAGE_TOO_BIG);
	}

	memcpy(x->request.bytes, nyoci_inbound_get_packet(), x->request_len);

	x->sockaddr_remote = *nyoci_plat_get_remote_sockaddr();
	x->sockaddr_local = *nyoci_plat_get_local_sockaddr();

	if ( !(flags & NYOCI_ASYNC_RESPONSE_FLAG_DONT_ACK)
	  && self->inbound.packet->tt == COAP_TRANS_TYPE_CONFIRMABLE
	) {
		// Fake inbound packets are created to tickle
		// content out of nodes by the pairing system.
		// Since we are asynchronous, this clearly isn't
		// going to work. Support for this will have to
		// come in the future.
		require_action(!(self->inbound.flags&NYOCI_INBOUND_FLAG_FAKE), bail, ret = NYOCI_STATUS_NOT_IMPLEMENTED);

		ret = nyoci_outbound_begin_response(COAP_CODE_EMPTY);
		require_noerr(ret, bail);

		ret = nyoci_outbound_send();
		require_noerr(ret, bail);
	}

	if (self->inbound.flags & NYOCI_INBOUND_FLAG_DUPE) {
		ret = NYOCI_STATUS_DUPE;
		goto bail;
	}

bail:
	return ret;
}

nyoci_status_t
nyoci_finish_async_response(struct nyoci_async_response_s* x) {
	x->request_len = 0;
	return NYOCI_STATUS_OK;
}

bool
nyoci_inbound_is_related_to_async_response(struct nyoci_async_response_s* x)
{
	const nyoci_sockaddr_t *curr_remote = nyoci_plat_get_remote_sockaddr();

	if (x->sockaddr_remote.nyoci_port != curr_remote->nyoci_port) {
		return false;
	}

	if (0 != memcmp(
		&x->sockaddr_remote.nyoci_addr,
		&curr_remote->nyoci_addr,
		sizeof(nyoci_addr_t)
	)) {
		return false;
	}

	if (x->request.header.code != nyoci_inbound_get_packet()->code) {
		return false;
	}

	if (x->request.header.token_len != nyoci_inbound_get_packet()->token_len) {
		return false;
	}

	if (0 != memcmp(
		x->request.header.token,
		nyoci_inbound_get_packet()->token,
		nyoci_inbound_get_packet()->token_len
	)) {
		return false;
	}

	return true;
}
