/*!	@file nyoci_internal.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
**	@brief Internal structures and functions
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

#ifndef __NYOCI_INTERNAL_H__
#define __NYOCI_INTERNAL_H__ 1

#include "libnyoci.h"
#include "string-utils.h"
#include "nyoci-dupe.h"
#include "nyoci-plat-net-internal.h"

#ifndef VERBOSE_DEBUG
#define VERBOSE_DEBUG 0
#endif

// TODO: Move this to the platform
#ifndef NYOCI_FUNC_RANDOM_UINT32
#if defined(__APPLE__)
#define NYOCI_FUNC_RANDOM_UINT32()   arc4random()
#define NYOCI_RANDOM_MAX			(uint32_t)(0xFFFFFFFF)
#elif CONTIKI
#include "lib/random.h"
#define NYOCI_FUNC_RANDOM_UINT32() \
		((uint32_t)random_rand() ^ \
			((uint32_t)random_rand() << 16))
#define NYOCI_RANDOM_MAX			RAND_MAX
#else
#define NYOCI_FUNC_RANDOM_UINT32() \
		((uint32_t)random() ^ \
			((uint32_t)random() << 16))
#define NYOCI_RANDOM_MAX			RAND_MAX
#endif
#endif

NYOCI_BEGIN_C_DECLS

#ifndef NYOCI_HOOK_TIMER_NEEDS_REFRESH
#define NYOCI_HOOK_TIMER_NEEDS_REFRESH(x)	do { } while (0)
#endif

// MARK: -
// MARK: Class Definitions

#if NYOCI_CONF_ENABLE_VHOSTS
struct nyoci_vhost_s {
	char name[64];
	nyoci_request_handler_func func;
	void* context;
};
#endif

// Consider members of this struct to be private!
struct nyoci_s {
	nyoci_request_handler_func	request_handler;
	void*						request_handler_context;

	struct nyoci_plat_s		plat;

	nyoci_timer_t			timers;

	nyoci_transaction_t		transactions;
	nyoci_transaction_t		current_transaction;

	// Operational Flags
	uint8_t					is_responding:1,
							did_respond:1,
							is_processing_message:1,
#if NYOCI_USE_CASCADE_COUNT
							has_cascade_count:1,
#endif
							force_current_outbound_code:1;

	coap_msg_id_t			last_msg_id;

	//! Inbound packet variables.
	struct {
		const struct coap_header_s*	packet;
		coap_size_t					packet_len;

		coap_option_key_t		last_option_key;
		const uint8_t*			this_option;

		const char*				content_ptr;
		coap_size_t				content_len;
		coap_content_type_t		content_type;

		uint8_t                 flags;

		uint32_t				transaction_hash;

		int32_t					max_age;
		uint32_t				observe_value;
		uint32_t				block2_value;
	} inbound;

	//! Outbound packet variables.
	struct {
		struct coap_header_s*	packet;
		coap_size_t				max_packet_len;

		char*					content_ptr;
		coap_size_t				content_len;

		coap_msg_id_t           next_tid;

		coap_option_key_t		last_option_key;
	} outbound;

	struct nyoci_dupe_info_s dupe_info;

	const char* proxy_url;

#if NYOCI_CONF_ENABLE_VHOSTS
	struct nyoci_vhost_s		vhost[NYOCI_MAX_VHOSTS];
	uint8_t					vhost_count;
#endif

#if NYOCI_USE_CASCADE_COUNT
	uint8_t					cascade_count;
#endif
};

//! Initializes an LibNyoci instance. Does not allocate any memory.
NYOCI_API_EXTERN nyoci_t nyoci_init(nyoci_t self);

NYOCI_INTERNAL_EXTERN nyoci_status_t nyoci_handle_request();

NYOCI_INTERNAL_EXTERN nyoci_status_t nyoci_handle_response();

NYOCI_INTERNAL_EXTERN nyoci_t nyoci_plat_init(nyoci_t self);
NYOCI_INTERNAL_EXTERN void nyoci_plat_finalize(nyoci_t self);

NYOCI_INTERNAL_EXTERN nyoci_status_t nyoci_outbound_set_var_content_int(int v);
NYOCI_INTERNAL_EXTERN nyoci_status_t nyoci_outbound_set_var_content_unsigned_int(unsigned int v);
NYOCI_INTERNAL_EXTERN nyoci_status_t nyoci_outbound_set_var_content_unsigned_long_int(unsigned long int v);


NYOCI_END_C_DECLS

#endif // __NYOCI_INTERNAL_H__
