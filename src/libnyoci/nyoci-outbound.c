/*	@file nyoci-outbound.c
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

#define __APPLE_USE_RFC_3542 1

#ifndef VERBOSE_DEBUG
#define VERBOSE_DEBUG 0
#endif

#ifndef DEBUG
#define DEBUG VERBOSE_DEBUG
#endif

#include "assert-macros.h"

#include "libnyoci.h"
#include "nyoci-internal.h"
#include "nyoci-logging.h"

#include "ll.h"
#include "url-helpers.h"

#if HAVE_ALLOCA_H
#include <alloca.h>
#endif

#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static uint8_t
nyoci_calc_uint32_option_size(uint32_t big_endian_value)
{
	if (((uint8_t*)(&big_endian_value))[0] != 0) {
		return 4;
	} else if (((uint8_t*)(&big_endian_value))[1] != 0) {
		return 3;
	} else if (((uint8_t*)(&big_endian_value))[2] != 0) {
		return 2;
	} else if (((uint8_t*)(&big_endian_value))[3] != 0) {
		return 1;
	}

	return 0;
}

// MARK: -
// MARK: Constrained sending API

void
nyoci_outbound_drop() {
	nyoci_t self = nyoci_get_current_instance();

	self->is_responding = false;
	self->did_respond = true;
}

void
nyoci_outbound_reset()
{
	memset(
		&nyoci_get_current_instance()->outbound,
		0,
		sizeof(nyoci_get_current_instance()->outbound)
	);
	nyoci_get_current_instance()->is_responding = false;
	nyoci_get_current_instance()->did_respond = false;
	if (!nyoci_get_current_instance()->is_processing_message) {
		nyoci_plat_set_session_type(NYOCI_SESSION_TYPE_UDP);
	}
}

nyoci_status_t
nyoci_outbound_begin(
	nyoci_t self, coap_code_t code, coap_transaction_type_t tt
) {
	nyoci_status_t ret = NYOCI_STATUS_FAILURE;
	NYOCI_SINGLETON_SELF_HOOK;

	check(!nyoci_get_current_instance() || nyoci_get_current_instance()==self);

	nyoci_set_current_instance(self);

#if NYOCI_USE_CASCADE_COUNT
	require_action(self->cascade_count != 1, bail, ret = NYOCI_STATUS_CASCADE_LOOP);
#endif

	if (!self->is_processing_message) {
		nyoci_plat_set_remote_sockaddr(NULL);
		nyoci_plat_set_local_sockaddr(NULL);
		nyoci_plat_set_session_type(NYOCI_SESSION_TYPE_UDP);
	}

	self->outbound.max_packet_len = NYOCI_MAX_PACKET_LENGTH;

	require_noerr((ret=nyoci_plat_outbound_start(self,(uint8_t**)&self->outbound.packet,&self->outbound.max_packet_len)), bail);

	assert(NULL != self->outbound.packet);

	self->outbound.packet->tt = tt;
	self->outbound.packet->msg_id = self->outbound.next_tid;
	self->outbound.packet->code = code;
	self->outbound.packet->version = COAP_VERSION;

	// Set the token.
	if ( self->is_processing_message
	  && self->inbound.packet != NULL
	  && self->inbound.packet->token_len != 0
	  && code != COAP_CODE_EMPTY
	) {
		self->outbound.packet->token_len = self->inbound.packet->token_len;
		memcpy(self->outbound.packet->token,self->inbound.packet->token,self->outbound.packet->token_len);

	} else if (code && (code < COAP_RESULT_100) && self->current_transaction) {
		// For sending a request.
		self->outbound.packet->token_len = sizeof(self->current_transaction->token);
		memcpy(self->outbound.packet->token,(void*)&self->current_transaction->token,self->outbound.packet->token_len);
	} else {
		self->outbound.packet->token_len = 0;
	}

	self->outbound.last_option_key = 0;

	self->outbound.content_ptr = (char*)self->outbound.packet->token + self->outbound.packet->token_len;
	*self->outbound.content_ptr++ = 0xFF;  // start-of-content marker
	self->outbound.content_len = 0;
	self->force_current_outbound_code = false;
	self->is_responding = false;

	ret = NYOCI_STATUS_OK;

bail:
	return ret;
}

nyoci_status_t nyoci_outbound_begin_response(coap_code_t code) {
	nyoci_status_t ret;
	nyoci_t const self = nyoci_get_current_instance();

	ret = NYOCI_STATUS_OK;

	require_action_string(!self->did_respond,
		bail,
		ret = NYOCI_STATUS_RESPONSE_NOT_ALLOWED,
		"Attempted to send more than one response!"
	);

	// If we have already started responding, don't bother.
	require_quiet(!self->is_responding, bail);

	if (self->is_processing_message) {
		self->outbound.next_tid = nyoci_inbound_get_msg_id();
	}

	ret = nyoci_outbound_begin(
		self,
		code,
		(self->inbound.packet->tt==COAP_TRANS_TYPE_NONCONFIRMABLE)?COAP_TRANS_TYPE_NONCONFIRMABLE:COAP_TRANS_TYPE_ACK
	);
	require_noerr(ret, bail);

	self->is_responding = true;

	if (self->is_processing_message) {
		require_noerr(ret=nyoci_outbound_set_msg_id(nyoci_inbound_get_msg_id()),bail);
	}
bail:
	if (ret != NYOCI_STATUS_OK) {
		self->is_responding = false;
	}
	return ret;
}

nyoci_status_t
nyoci_outbound_set_msg_id(coap_msg_id_t tid) {
	assert(nyoci_get_current_instance()->outbound.packet);
	nyoci_get_current_instance()->outbound.packet->msg_id = tid;
	return NYOCI_STATUS_OK;
}

nyoci_status_t
nyoci_outbound_set_code(coap_code_t code) {
	nyoci_t const self = nyoci_get_current_instance();
	if (!self->force_current_outbound_code) {
		self->outbound.packet->code = code;
	}
	return NYOCI_STATUS_OK;
}

nyoci_status_t
nyoci_outbound_set_token(const uint8_t *token,uint8_t token_length) {
	nyoci_status_t ret;
	nyoci_t const self = nyoci_get_current_instance();

	ret = NYOCI_STATUS_OK;

	require_action(token_length<=8,bail,ret=NYOCI_STATUS_INVALID_ARGUMENT);

	if (self->outbound.packet->token_len != token_length) {
		self->outbound.packet->token_len = token_length;
		self->outbound.content_ptr = (char*)self->outbound.packet->token+self->outbound.packet->token_len;
		self->outbound.content_len = 0;
		*self->outbound.content_ptr++ = 0xFF;
	}

	if (token_length > 0) {
		memcpy(self->outbound.packet->token,token,token_length);
	}

bail:
	return ret;
}

static nyoci_status_t
nyoci_outbound_add_option_(
	coap_option_key_t key, const char* value, coap_size_t len
) {
	nyoci_t const self = nyoci_get_current_instance();

	if (len == NYOCI_CSTR_LEN) {
		len = (coap_size_t)strlen(value);
	}

	if (nyoci_outbound_get_space_remaining() < len + 8 ) {
		// We ran out of room!
		return NYOCI_STATUS_MESSAGE_TOO_BIG;
	}

	if (key < self->outbound.last_option_key) {
		// This is just a performance issue.
		assert_printf("warning: Out of order header: %s",coap_option_key_to_cstr(key, self->is_responding));
	}

	if (self->outbound.content_ptr != (char*)self->outbound.packet->token + self->outbound.packet->token_len) {
		self->outbound.content_ptr--;	// remove end-of-options marker
	}

	self->outbound.content_ptr += coap_insert_option(
		(uint8_t*)self->outbound.packet->token+self->outbound.packet->token_len,
		(uint8_t*)self->outbound.content_ptr,
		key,
		(const uint8_t*)value,
		len
	);

	if (key>self->outbound.last_option_key) {
		self->outbound.last_option_key = key;
	}

	*self->outbound.content_ptr++ = 0xFF;  // Add end-of-options marker

#if OPTION_DEBUG
	coap_dump_header(
		NYOCI_DEBUG_OUT_FILE,
		"Option-Debug >>> ",
		self->outbound.packet,
		self->outbound.content_ptr-(char*)self->outbound.packet
	);
#endif

	return NYOCI_STATUS_OK;
}

static nyoci_status_t
nyoci_outbound_add_options_up_to_key_(
	coap_option_key_t key
) {
	nyoci_status_t ret = NYOCI_STATUS_OK;
	nyoci_t const self = nyoci_get_current_instance();

	(void)self;

#if NYOCI_CONF_TRANS_ENABLE_BLOCK2
	if(	(self->current_transaction
		&& self->current_transaction->next_block2)
		&& self->outbound.last_option_key<COAP_OPTION_BLOCK2
		&& key>COAP_OPTION_BLOCK2
	) {
		uint32_t block2 = htonl(self->current_transaction->next_block2);
		uint8_t size = nyoci_calc_uint32_option_size(block2);
		ret = nyoci_outbound_add_option_(
			COAP_OPTION_BLOCK2,
			(char*)&block2+4-size,
			size
		);
	}
#endif

#if NYOCI_CONF_TRANS_ENABLE_OBSERVING
	if(	(self->current_transaction && self->current_transaction->flags&NYOCI_TRANSACTION_OBSERVE)
		&& self->outbound.last_option_key<COAP_OPTION_OBSERVE
		&& key>COAP_OPTION_OBSERVE
	) {
		if(self->outbound.packet->code && self->outbound.packet->code<COAP_RESULT_100) {
			// For sending a request.
			ret = nyoci_outbound_add_option_(
				COAP_OPTION_OBSERVE,
				(void*)NULL,
				0
			);
		}
	}
#endif

#if NYOCI_USE_CASCADE_COUNT
	if(	self->outbound.last_option_key<COAP_OPTION_CASCADE_COUNT
		&& key>COAP_OPTION_CASCADE_COUNT
		&& self->cascade_count
	) {
		uint8_t cc = self->cascade_count-1;
		ret = nyoci_outbound_add_option_(
			COAP_OPTION_CASCADE_COUNT,
			(char*)&cc,
			1
		);
	}
#endif

	return ret;
}

nyoci_status_t
nyoci_outbound_add_option(
	coap_option_key_t key, const char* value, coap_size_t len
) {
	nyoci_status_t ret;

	ret = nyoci_outbound_add_options_up_to_key_(key);
	require_noerr(ret, bail);

#if NYOCI_CONF_TRANS_ENABLE_BLOCK2
	if ( key == COAP_OPTION_BLOCK2
	  && nyoci_get_current_instance()->current_transaction
	  && nyoci_get_current_instance()->current_transaction->next_block2
	) {
		goto bail;
	}
#endif

	ret = nyoci_outbound_add_option_(key,value,len);
	require_noerr(ret, bail);

bail:
	return ret;
}

nyoci_status_t
nyoci_outbound_add_option_uint(coap_option_key_t key,uint32_t value)
{
	uint8_t size;

	value = htonl(value);
	size = nyoci_calc_uint32_option_size(value);

	return nyoci_outbound_add_option(key, ((char*)&value)+(4-size), size);
}

nyoci_status_t
nyoci_outbound_set_uri(
	const char* uri, char flags
) {
	nyoci_status_t ret = NYOCI_STATUS_OK;
	nyoci_t const self = nyoci_get_current_instance();
	NYOCI_NON_RECURSIVE struct url_components_s components;
	NYOCI_NON_RECURSIVE uint16_t toport;
	NYOCI_NON_RECURSIVE char* uri_copy;

	memset((void*)&components, 0, sizeof(components));
	toport = COAP_DEFAULT_PORT;
	uri_copy = NULL;

	require_action(uri, bail, ret = NYOCI_STATUS_INVALID_ARGUMENT);

	{
#if HAVE_ALLOCA
		uri_copy = alloca(strlen(uri) + 1);
		strcpy(uri_copy, uri);
#elif NYOCI_AVOID_MALLOC
		// Well, we can't use the stack and we can't
		// use malloc. Let's use what room we have left
		// in the packet buffer, since this is temporary anyway...
		// It helps a bunch that we know the user hasn't written
		// any content yet (because that would be an API violation)
		//
		// The options section may be expanding as we parse this, so
		// we require at least `uri_padding` bytes of padding between
		// the end of the options and the start of the URI are free.
		// We are ultimately helped out by the fact that we will be
		// writing the options in the same order they appear in the
		// URL, and that we will ultimately be copying the values
		// using `memmove()`.
		static const int uri_padding = 16;
		if (nyoci_outbound_get_space_remaining() > strlen(uri) + uri_padding) {
			uri_copy = (char*)self->outbound.packet
				+ self->outbound.max_packet_len
				- (strlen(uri) + 1); // Plus 1 for NUL

			strcpy(uri_copy, uri);
		}
#else
		uri_copy = strdup(uri);
#endif

		require_action(uri_copy != NULL, bail, ret = NYOCI_STATUS_MALLOC_FAILURE);

		// Parse the URI.
		require_action_string(
			url_parse(
				uri_copy,
				&components
			),
			bail,
			ret = NYOCI_STATUS_URI_PARSE_FAILURE,
			"Unable to parse URL"
		);

		if(!components.protocol && !components.host) {
			// Talking to ourself.
			components.protocol = "coap";
			components.host = "::1";
			toport = nyoci_plat_get_port(nyoci_get_current_instance());
			flags |= NYOCI_MSG_SKIP_AUTHORITY;
		} else if(components.port) {
			toport = (uint16_t)atoi(components.port);
		}

		DEBUG_PRINTF(
			"URI Parse: \"%s\" -> host=\"%s\" port=\"%u\" path=\"%s\"",
			uri,
			components.host,
			toport,
			components.path
		);
	}

	if (components.protocol) {
		nyoci_session_type_t session_type = nyoci_session_type_from_uri_scheme(components.protocol);
		nyoci_plat_set_session_type(session_type);

		if (NULL == components.port) {
			toport = nyoci_default_port_from_session_type(session_type);
		}

		if (session_type == NYOCI_SESSION_TYPE_NIL) {
			require_action_string(
				self->proxy_url,
				bail,
				ret=NYOCI_STATUS_INVALID_ARGUMENT,
				"No proxy URL configured"
			);
			require_action(uri != self->proxy_url,bail,ret = NYOCI_STATUS_INVALID_ARGUMENT);

			ret = nyoci_outbound_add_option(COAP_OPTION_PROXY_URI, uri, NYOCI_CSTR_LEN);
			require_noerr(ret, bail);
			ret = nyoci_outbound_set_uri(self->proxy_url,flags);
			goto bail;
		}
	}

	if (!(flags & NYOCI_MSG_SKIP_AUTHORITY)) {
		if(components.host && !string_contains_colons(components.host)) {
			ret = nyoci_outbound_add_option(COAP_OPTION_URI_HOST, components.host, NYOCI_CSTR_LEN);
			require_noerr(ret, bail);
		}
		if(components.port) {
			ret = nyoci_outbound_add_option_uint(COAP_OPTION_URI_PORT, toport);
			require_noerr(ret, bail);
		}
	}


	if ( !(flags & NYOCI_MSG_SKIP_DESTADDR)
	  && components.host && components.host[0]!=0
	) {
		ret = nyoci_plat_set_remote_hostname_and_port(
			components.host,
			toport
		);
		require_noerr(ret, bail);
	}

	if (components.path) {
		NYOCI_NON_RECURSIVE char* component;
		const bool has_trailing_slash = components.path[0]?('/' == components.path[strlen(components.path)-1]):false;

		// Move past any preceding slashes.
		while (components.path[0] == '/') {
			components.path++;
		}

		while (url_path_next_component(&components.path,&component)) {
			ret = nyoci_outbound_add_option(COAP_OPTION_URI_PATH, component, NYOCI_CSTR_LEN);
			require_noerr(ret,bail);
		}

		if (has_trailing_slash) {
			ret = nyoci_outbound_add_option(COAP_OPTION_URI_PATH, NULL, 0);
			require_noerr(ret,bail);
		}
	}

	if (components.query) {
		NYOCI_NON_RECURSIVE char* key;

		while (url_form_next_value(&components.query, &key, NULL)) {
			coap_size_t len = (coap_size_t)strlen(key);

			if (len) {
				ret = nyoci_outbound_add_option(COAP_OPTION_URI_QUERY, key, len);
			}
			require_noerr(ret,bail);
		}
	}

bail:
	if(ret) {
		DEBUG_PRINTF("URI Parse failed for URI: \"%s\"",uri);
	}

#if !HAVE_ALLOCA && !NYOCI_AVOID_MALLOC
	free(uri_copy);
#endif

	return ret;
}

coap_size_t
nyoci_outbound_get_space_remaining(void)
{
	nyoci_t const self = nyoci_get_current_instance();
	coap_size_t len = (coap_size_t)(self->outbound.content_ptr-(char*)self->outbound.packet)
		+ self->outbound.content_len;
	if (self->outbound.max_packet_len > len) {
		return self->outbound.max_packet_len - len;
	}
	return 0;
}

nyoci_status_t
nyoci_outbound_append_content(const char* value, coap_size_t len)
{
	nyoci_status_t ret = NYOCI_STATUS_FAILURE;
	nyoci_t const self = nyoci_get_current_instance();
	coap_size_t max_len = nyoci_outbound_get_space_remaining();
	char* dest;

	if (NYOCI_CSTR_LEN == len) {
		len = (coap_size_t)strlen(value);
	}

	require_action(max_len>len, bail, ret = NYOCI_STATUS_MESSAGE_TOO_BIG);

	dest = nyoci_outbound_get_content_ptr(&max_len);
	require(dest,bail);

	dest += self->outbound.content_len;

	memcpy(dest, value, len);

	self->outbound.content_len += len;

	ret = NYOCI_STATUS_OK;

bail:
	return ret;
}

char*
nyoci_outbound_get_content_ptr(coap_size_t* max_len)
{
	nyoci_t const self = nyoci_get_current_instance();

	assert(NULL!=self->outbound.packet);

	// Finish up any remaining automatically-added headers.
	if (self->outbound.packet->code) {
		nyoci_outbound_add_options_up_to_key_(COAP_OPTION_INVALID);
	}

	if (max_len) {
		*max_len = nyoci_outbound_get_space_remaining()+self->outbound.content_len;
	}

	return self->outbound.content_ptr;
}

nyoci_status_t
nyoci_outbound_set_content_len(coap_size_t len)
{
	nyoci_get_current_instance()->outbound.content_len = len;
	return NYOCI_STATUS_OK;
}


// MARK: -

#if !NYOCI_AVOID_PRINTF
nyoci_status_t
nyoci_outbound_append_content_formatted(const char* fmt, ...)
{
	nyoci_status_t ret = NYOCI_STATUS_FAILURE;
	va_list args;
	nyoci_t const self = nyoci_get_current_instance();
	char* content = nyoci_outbound_get_content_ptr(NULL);
	const coap_size_t len = nyoci_outbound_get_space_remaining();
	int fmtlen;

	require(content!=NULL, bail);

	content += self->outbound.content_len;

	va_start(args,fmt);

	fmtlen = vsnprintf(content, len, fmt, args);

	require(fmtlen >= 0, bail);

	require(fmtlen <= len, bail);

	fmtlen += self->outbound.content_len;

	ret = nyoci_outbound_set_content_len((coap_size_t)fmtlen);

bail:
	va_end(args);
	return ret;
}
#endif

nyoci_status_t
nyoci_outbound_set_var_content_int(int v)
{
	nyoci_outbound_set_content_len(0);
	nyoci_outbound_add_option_uint(
		COAP_OPTION_CONTENT_TYPE,
		NYOCI_CONTENT_TYPE_APPLICATION_FORM_URLENCODED
	);
#if NYOCI_AVOID_PRINTF
	{
		char nstr[12];
		nyoci_outbound_append_content("v=", NYOCI_CSTR_LEN);
		return nyoci_outbound_append_content(int32_to_dec_cstr(nstr,v), NYOCI_CSTR_LEN);
	}
#else
	return nyoci_outbound_append_content_formatted_const("v=%d",v);
#endif
}

nyoci_status_t
nyoci_outbound_set_var_content_unsigned_int(unsigned int v)
{
	nyoci_outbound_set_content_len(0);
	nyoci_outbound_add_option_uint(
		COAP_OPTION_CONTENT_TYPE,
		NYOCI_CONTENT_TYPE_APPLICATION_FORM_URLENCODED
	);
#if NYOCI_AVOID_PRINTF
	{
		char nstr[12];
		nyoci_outbound_append_content("v=", NYOCI_CSTR_LEN);
		return nyoci_outbound_append_content(uint32_to_dec_cstr(nstr,v), NYOCI_CSTR_LEN);
	}
#else
	return nyoci_outbound_append_content_formatted_const("v=%u",v);
#endif
}

nyoci_status_t
nyoci_outbound_set_var_content_unsigned_long_int(unsigned long int v)
{
	nyoci_outbound_set_content_len(0);
	nyoci_outbound_add_option_uint(
		COAP_OPTION_CONTENT_TYPE,
		NYOCI_CONTENT_TYPE_APPLICATION_FORM_URLENCODED
	);
#if NYOCI_AVOID_PRINTF
{
		char nstr[12];
		nyoci_outbound_append_content("v=", NYOCI_CSTR_LEN);
		return nyoci_outbound_append_content(uint32_to_dec_cstr(nstr,v), NYOCI_CSTR_LEN);
	}
#else
	return nyoci_outbound_append_content_formatted_const("v=%ul",v);
#endif
}


nyoci_status_t
nyoci_outbound_quick_response(coap_code_t code, const char* body)
{
	nyoci_outbound_begin_response(code);
	if (body) {
		nyoci_outbound_append_content(body, NYOCI_CSTR_LEN);
	}
	return nyoci_outbound_send();
}

nyoci_status_t
nyoci_outbound_send(void)
{
	nyoci_status_t ret = NYOCI_STATUS_FAILURE;
	nyoci_t const self = nyoci_get_current_instance();

	coap_size_t header_len = (coap_size_t)(nyoci_outbound_get_content_ptr(NULL)-(char*)self->outbound.packet);

	// Remove the start-of-payload marker if we have no payload.
	if (!self->outbound.content_len) {
		header_len--;
	}

	if (self->outbound.packet->code == COAP_CODE_EMPTY) {
		self->outbound.content_len = 0;
		header_len = sizeof(struct coap_header_s);
	}

#if DEBUG
	{
		DEBUG_PRINTF("Outbound packet size: %d, %d remaining",header_len+self->outbound.content_len, nyoci_outbound_get_space_remaining());
		assert(header_len+self->outbound.content_len<=self->outbound.max_packet_len);

		assert(coap_verify_packet((char*)self->outbound.packet,header_len+nyoci_get_current_instance()->outbound.content_len));
	}
#endif // DEBUG

	if (self->current_transaction) {
		self->current_transaction->sent_code = self->outbound.packet->code;
		self->current_transaction->sockaddr_remote = *nyoci_plat_get_remote_sockaddr();
		self->current_transaction->multicast = NYOCI_IS_ADDR_MULTICAST(&self->current_transaction->sockaddr_remote.nyoci_addr);
	}

#if defined(NYOCI_DEBUG_OUTBOUND_DROP_PERCENT)
	if(NYOCI_DEBUG_OUTBOUND_DROP_PERCENT*NYOCI_RANDOM_MAX>NYOCI_FUNC_RANDOM_UINT32()) {
		DEBUG_PRINTF("Dropping outbound packet for debugging!");
		if(nyoci_get_current_instance()->is_responding)
			nyoci_get_current_instance()->did_respond = true;
		nyoci_get_current_instance()->is_responding = false;

		ret = NYOCI_STATUS_OK;
		goto bail;
	}
#endif

	if ((self->outbound.packet->tt == COAP_TRANS_TYPE_ACK)
		&& nyoci_session_type_is_reliable(nyoci_plat_get_session_type())
	) {
		// If the session type is reliable, we don't bother
		// sending acks.
	} else {
		ret = nyoci_plat_outbound_finish(
			self,
			(const uint8_t*)self->outbound.packet,
			header_len + self->outbound.content_len,
			0 // FLAGS
		);
	}


	require(ret == NYOCI_STATUS_OK, bail);

	if (self->is_responding) {
		self->did_respond = true;
	}
	self->is_responding = false;

	ret = NYOCI_STATUS_OK;
bail:
	return ret;
}
