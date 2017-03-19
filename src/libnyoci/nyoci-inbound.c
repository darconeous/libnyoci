/*	@file nyoci-inbound.c
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

#if HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef VERBOSE_DEBUG
#define VERBOSE_DEBUG 0
#endif

#ifndef DEBUG
#define DEBUG VERBOSE_DEBUG
#endif

#define __APPLE_USE_RFC_3542 1

#include "assert-macros.h"

#include "libnyoci.h"
#include "nyoci-internal.h"
#include "nyoci-logging.h"
#include "nyoci-timer.h"

#include "url-helpers.h"
#include "ll.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>


// MARK: -
// MARK: Simple inbound getters

const struct coap_header_s*
nyoci_inbound_get_packet() {
	return nyoci_get_current_instance()->inbound.packet;
}

coap_size_t nyoci_inbound_get_packet_length() {
	return nyoci_get_current_instance()->inbound.packet_len;
}

const char*
nyoci_inbound_get_content_ptr() {
	return nyoci_get_current_instance()->inbound.content_ptr;
}

coap_size_t
nyoci_inbound_get_content_len() {
	return nyoci_get_current_instance()->inbound.content_len;
}

coap_content_type_t
nyoci_inbound_get_content_type() {
	return nyoci_get_current_instance()->inbound.content_type;
}

uint16_t
nyoci_inbound_get_flags() {
	return nyoci_get_current_instance()->inbound.flags;
}

// MARK: -
// MARK: Option Parsing

void
nyoci_inbound_reset_next_option() {
	nyoci_t const self = nyoci_get_current_instance();
	self->inbound.last_option_key = 0;
	self->inbound.this_option = self->inbound.packet->token + self->inbound.packet->token_len;
}

coap_option_key_t
nyoci_inbound_next_option(const uint8_t** value, coap_size_t* len) {
	nyoci_t const self = nyoci_get_current_instance();

	if ( self->inbound.this_option    <  ((uint8_t*)self->inbound.packet+self->inbound.packet_len)
	  && self->inbound.this_option[0] != 0xFF
	) {
		self->inbound.this_option = coap_decode_option(
			self->inbound.this_option,
			&self->inbound.last_option_key,
			value,
			len
		);

	} else {
		self->inbound.last_option_key = COAP_OPTION_INVALID;
	}
	return self->inbound.last_option_key;
}

coap_option_key_t
nyoci_inbound_peek_option(const uint8_t** value, coap_size_t* len) {
	nyoci_t const self = nyoci_get_current_instance();
	coap_option_key_t ret = self->inbound.last_option_key;

	if ( self->inbound.last_option_key != COAP_OPTION_INVALID
	  && self->inbound.this_option     <  ((uint8_t*)self->inbound.packet+self->inbound.packet_len)
	  && self->inbound.this_option[0]  != 0xFF
	) {
		coap_decode_option(
			self->inbound.this_option,
			&ret,
			value,
			len
		);

	} else {
		ret = COAP_OPTION_INVALID;
	}
	return ret;
}

bool
nyoci_inbound_option_strequal(coap_option_key_t key,const char* cstr) {
	nyoci_t const self = nyoci_get_current_instance();
	coap_option_key_t curr_key = self->inbound.last_option_key;
	const char* value;
	coap_size_t value_len;
	coap_size_t i;

	if (!self->inbound.this_option) {
		return false;
	}

	coap_decode_option(self->inbound.this_option, &curr_key, (const uint8_t**)&value, &value_len);

	if (curr_key != key) {
		return false;
	}

	for (i = 0; i < value_len; i++) {
		if(!cstr[i] || (value[i] != cstr[i])) {
			return false;
		}
	}
	return cstr[i]==0;
}

// MARK: -
// MARK: Nontrivial inbound getters

char*
nyoci_inbound_get_path(char* where, uint8_t flags)
{
	nyoci_t const self = nyoci_get_current_instance();

	coap_option_key_t		last_option_key = self->inbound.last_option_key;
	const uint8_t*			this_option = self->inbound.this_option;

	char* filename;
	coap_size_t filename_len;
	coap_option_key_t key;
	char* iter;

#if !NYOCI_AVOID_MALLOC
	if (!where) {
		where = calloc(1, NYOCI_MAX_URI_LENGTH + 1);
	}
#endif

	require(where != NULL, bail);

	iter = where;

	if ((flags & NYOCI_GET_PATH_REMAINING) != NYOCI_GET_PATH_REMAINING) {
		nyoci_inbound_reset_next_option();
	}

	while ((key = nyoci_inbound_peek_option(NULL,NULL))!=COAP_OPTION_URI_PATH
		&& key!=COAP_OPTION_INVALID
	) {
		nyoci_inbound_next_option(NULL,NULL);
	}

	while (nyoci_inbound_next_option((const uint8_t**)&filename, &filename_len)==COAP_OPTION_URI_PATH) {
		char old_end = filename[filename_len];
		if(iter!=where || (flags&NYOCI_GET_PATH_LEADING_SLASH))
			*iter++='/';
		filename[filename_len] = 0;
		iter+=url_encode_cstr(iter, filename, NYOCI_MAX_URI_LENGTH-(iter-where));
		filename[filename_len] = old_end;
	}

	if (flags & NYOCI_GET_PATH_INCLUDE_QUERY) {
		nyoci_inbound_reset_next_option();
		while((key = nyoci_inbound_peek_option((const uint8_t**)&filename, &filename_len))!=COAP_OPTION_URI_QUERY
			&& key!=COAP_OPTION_INVALID
		) {
			nyoci_inbound_next_option(NULL,NULL);
		}
		if (key == COAP_OPTION_URI_QUERY) {
			*iter++='?';
			while (nyoci_inbound_next_option((const uint8_t**)&filename, &filename_len)==COAP_OPTION_URI_QUERY) {
				char old_end = filename[filename_len];
				char* equal_sign;

				if (iter[-1] != '?') {
					*iter++=';';
				}

				filename[filename_len] = 0;
				equal_sign = strchr(filename,'=');

				if (equal_sign) {
					*equal_sign = 0;
				}

				iter+=url_encode_cstr(iter, filename, NYOCI_MAX_URI_LENGTH-(iter-where));

				if (equal_sign) {
					*iter++='=';
					iter+=url_encode_cstr(iter, equal_sign+1, NYOCI_MAX_URI_LENGTH-(iter-where));
					*equal_sign = '=';
				}
				filename[filename_len] = old_end;
			}
		}
	}

	*iter = 0;

	self->inbound.last_option_key = last_option_key;
	self->inbound.this_option = this_option;

bail:
	return where;
}

// MARK: -
// MARK: Inbound packet processing

nyoci_status_t
nyoci_inbound_packet_process(
	nyoci_t self,
	char* buffer,
	coap_size_t packet_length,
	int flags
) {
	NYOCI_SINGLETON_SELF_HOOK;
	nyoci_status_t ret = 0;
	struct coap_header_s* const packet = (void*)buffer; // Should not use stack space.

	require_action(coap_verify_packet(buffer,packet_length),bail,ret=NYOCI_STATUS_BAD_PACKET);

#if defined(NYOCI_DEBUG_INBOUND_DROP_PERCENT)
	if ((uint32_t)(NYOCI_DEBUG_INBOUND_DROP_PERCENT*NYOCI_RANDOM_MAX)>NYOCI_FUNC_RANDOM_UINT32()) {
		DEBUG_PRINTF("Dropping inbound packet for debugging!");
		goto bail;
	}
#endif

	nyoci_set_current_instance(self);

	// Reset all inbound packet state.
	memset(&self->inbound,0,sizeof(self->inbound));

	// We are processing a message.
	self->is_processing_message = true;
	self->did_respond = false;

	self->inbound.packet = packet;
	self->inbound.packet_len = packet_length;
	self->inbound.content_type = COAP_CONTENT_TYPE_UNKNOWN;

	self->current_transaction = NULL;

	{
		const nyoci_sockaddr_t* const l_saddr = nyoci_plat_get_local_sockaddr();
		const nyoci_sockaddr_t* const r_saddr = nyoci_plat_get_remote_sockaddr();

		if (NYOCI_IS_ADDR_MULTICAST(&l_saddr->nyoci_addr)) {
			self->inbound.flags |= NYOCI_INBOUND_FLAG_MULTICAST;
		}

		if ( (l_saddr->nyoci_port == r_saddr->nyoci_port)
		  && (0 == memcmp(&l_saddr->nyoci_addr, &r_saddr->nyoci_addr, sizeof(r_saddr->nyoci_addr)))
		) {
			self->inbound.flags |= NYOCI_INBOUND_FLAG_LOCAL;
		}
	}

#if NYOCI_USE_CASCADE_COUNT
	self->cascade_count = NYOCI_MAX_CASCADE_COUNT;
#endif

	// Make sure there is a zero at the end of the packet, so that
	// if the content is a string it will be conveniently zero terminated.
	// Kind of a hack, but very convenient.
	buffer[packet_length] = 0;

#if VERBOSE_DEBUG
	{
		char addr_str[50] = "???";
		uint16_t port = ntohs(nyoci_plat_get_remote_sockaddr()->nyoci_port);
		NYOCI_ADDR_NTOP(addr_str,sizeof(addr_str),&nyoci_plat_get_remote_sockaddr()->nyoci_addr);
		DEBUG_PRINTF("nyoci(%p): Inbound packet from [%s]:%d", self, addr_str, (int)port);
		coap_dump_header(
			NYOCI_DEBUG_OUT_FILE,
			"Inbound:\t",
			(struct coap_header_s*)self->inbound.packet,
			self->inbound.packet_len
		);
	}
#endif

	if (self->inbound.flags & NYOCI_INBOUND_FLAG_MULTICAST) {
		// If this was multicast, make sure it isn't confirmable.
		require_action(
			packet->tt != COAP_TRANS_TYPE_CONFIRMABLE,
			bail,
			ret = NYOCI_STATUS_FAILURE
		);
	}

	if ((flags & NYOCI_INBOUND_PACKET_TRUNCATED) == NYOCI_INBOUND_PACKET_TRUNCATED) {
		ret = nyoci_outbound_quick_response(
			COAP_RESULT_413_REQUEST_ENTITY_TOO_LARGE,
			"too-big"
		);
		check_noerr(ret);
		goto bail;
	}

	if (!(self->inbound.flags & NYOCI_INBOUND_FLAG_FAKE) && nyoci_inbound_dupe_check()) {
		self->inbound.flags |= NYOCI_INBOUND_FLAG_DUPE;
	}

	{	// Initial scan thru all of the options.
		const uint8_t* value;
		coap_size_t value_len;
		coap_option_key_t key;

		// Reset option scanner for initial option scan.
		nyoci_inbound_reset_next_option();

		while((key = nyoci_inbound_next_option(&value,&value_len)) != COAP_OPTION_INVALID) {
			switch(key) {
			case COAP_OPTION_CONTENT_TYPE:
				self->inbound.content_type = (coap_content_type_t)coap_decode_uint32(value,(uint8_t)value_len);
				break;

			case COAP_OPTION_OBSERVE:
				self->inbound.observe_value = coap_decode_uint32(value,(uint8_t)value_len);
				self->inbound.flags |= NYOCI_INBOUND_FLAG_HAS_OBSERVE;
				break;

			case COAP_OPTION_MAX_AGE:
				self->inbound.max_age = coap_decode_uint32(value,(uint8_t)value_len);
				self->inbound.max_age++;
				if (self->inbound.max_age < 5)
					self->inbound.max_age = 5;
				break;

			case COAP_OPTION_BLOCK2:
				self->inbound.block2_value = coap_decode_uint32(value,(uint8_t)value_len);
				break;

#if NYOCI_USE_CASCADE_COUNT
			case COAP_OPTION_CASCADE_COUNT:
				self->cascade_count = coap_decode_uint32(value,(uint8_t)value_len);
				break;
#endif

			default:
				break;
			}
		}
	}

	// Sanity check on debug builds.
	check(((unsigned)(self->inbound.this_option-(uint8_t*)packet)==self->inbound.packet_len) || self->inbound.this_option[0]==0xFF);

	// Now that we are at the end of the options, we know
	// where the content starts.
	self->inbound.content_ptr = (char*)self->inbound.this_option;
	self->inbound.content_len = (self->inbound.packet_len-(coap_size_t)((uint8_t*)self->inbound.content_ptr-(uint8_t*)packet));

	// Move past start-of-content marker.
	if (self->inbound.content_len > 0) {
		self->inbound.content_ptr++;
		self->inbound.content_len--;
	}

	// Be nice and reset the option scanner for the handler.
	nyoci_inbound_reset_next_option();

	// Dispatch the packet to the appropriate handler.
	if (COAP_CODE_IS_REQUEST(packet->code)) {
		// Implementation of the following function is further
		// down in this file.
		ret = nyoci_handle_request();

	} else if (COAP_CODE_IS_RESULT(packet->code)) {
		// See implementation in `nyoci-transaction.c`.
		ret = nyoci_handle_response();
	}

	check_string(ret == NYOCI_STATUS_OK, nyoci_status_to_cstr(ret));

	// Check to make sure we have responded by now. If not, we need to.
	if (!self->did_respond && (packet->tt==COAP_TRANS_TYPE_CONFIRMABLE)) {
		nyoci_status_t original_ret = ret;

#if NYOCI_USE_BSD_SOCKETS
		int original_errno = errno;
#endif

		nyoci_outbound_reset();

		if (COAP_CODE_IS_REQUEST(packet->code)) {
			coap_code_t result_code = nyoci_convert_status_to_result_code(original_ret);

			if (self->inbound.flags & NYOCI_INBOUND_FLAG_DUPE) {
				ret = 0;
			}

			if (ret == NYOCI_STATUS_OK) {
				if (packet->code == COAP_METHOD_GET) {
					result_code = COAP_RESULT_205_CONTENT;
				} else if (packet->code == COAP_METHOD_POST || packet->code == COAP_METHOD_PUT) {
					result_code = COAP_RESULT_204_CHANGED;
				} else if (packet->code == COAP_METHOD_DELETE) {
					result_code = COAP_RESULT_202_DELETED;
				}
			}

			ret = nyoci_outbound_begin_response(result_code);

			require_noerr(ret, bail);

			// For an ISE, let's give a little more information.
			if (result_code == COAP_RESULT_500_INTERNAL_SERVER_ERROR) {
				nyoci_outbound_set_var_content_int(original_ret);
#if NYOCI_USE_BSD_SOCKETS
				nyoci_outbound_append_content(";d=\"", NYOCI_CSTR_LEN);
				errno = original_errno;
				nyoci_outbound_append_content(nyoci_status_to_cstr(original_ret), NYOCI_CSTR_LEN);
				nyoci_outbound_append_content("\"", NYOCI_CSTR_LEN);
#endif
			}
		} else { // !COAP_CODE_IS_REQUEST(packet->code)
			// This isn't a request, so we send either an ACK,
			// or a RESET.
			ret = nyoci_outbound_begin_response(COAP_CODE_EMPTY);

			require_noerr(ret, bail);

			if ((ret != NYOCI_STATUS_OK) && !(self->inbound.flags & NYOCI_INBOUND_FLAG_DUPE)) {
				self->outbound.packet->tt = COAP_TRANS_TYPE_RESET;
			} else {
				self->outbound.packet->tt = COAP_TRANS_TYPE_ACK;
			}

			nyoci_outbound_set_token(NULL, 0);
		}
		ret = nyoci_outbound_send();
	}

bail:
	self->is_processing_message = false;
	self->force_current_outbound_code = false;
	self->inbound.packet = NULL;
	self->inbound.content_ptr = NULL;
	self->inbound.content_len = 0;
	nyoci_set_current_instance(NULL);
	return ret;
}

// MARK: -
// MARK: Request Handler

nyoci_status_t
nyoci_handle_request(void)
{
	nyoci_status_t ret = NYOCI_STATUS_NOT_FOUND;
	nyoci_t const self = nyoci_get_current_instance();
	nyoci_request_handler_func request_handler = self->request_handler;
	void* context = self->request_handler_context;

#if VERBOSE_DEBUG
	{   // Print out debugging information.
		DEBUG_PRINTF(
			"nyoci(%p): %sIncoming request!",
			self,
			(self->inbound.flags & NYOCI_INBOUND_FLAG_FAKE)?"(FAKE) ":""
		);
	}
#endif

	// TODO: Add proxy-server handler.

#if NYOCI_CONF_ENABLE_VHOSTS
	{
		extern nyoci_status_t nyoci_vhost_route(nyoci_request_handler_func* func, void** context);
		ret = nyoci_vhost_route(&request_handler, &context);
		require_noerr(ret, bail);
	}
#endif

	require_action(NULL!=request_handler,bail,ret=NYOCI_STATUS_NOT_IMPLEMENTED);

	nyoci_inbound_reset_next_option();

	return (*request_handler)(context);

bail:
	return ret;
}
