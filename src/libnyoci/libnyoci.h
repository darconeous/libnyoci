/*!	@file nyoci.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
**	@brief Primary header
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

/*!	@mainpage LibNyoci - A C-Based CoAP Stack
**	LibNyoci is a C-based CoAP stack which is suitable for embedded environments.
**	Features include:
**
**	 * Supports RFC7252 <http://tools.ietf.org/html/rfc7252>.
**	 * Fully asynchronous I/O.
**	 * Supports both BSD sockets and [uIP](http://en.wikipedia.org/wiki/UIP_(micro_IP%29).
**	 * Supports sending and receiving asynchronous CoAP responses.
**	 * Supports observing resources and offering observable resources.
**	 * Supports retransmission of confirmable transactions.
**	 * `nyocictl` - a powerful command line tool for browsing and configuring CoAP nodes.
**
**	## Contiki Support ##
**
**	LibNyoci supports [Contiki](http://contiki-os.org/). To build the Contiki
**  examples, just make sure that the `CONTIKI` environment variable is set
**  point to your Contiki root, like so:
**
**		$ cd contiki-src/examples/nyoci-simple
**		$ make CONTIKI=~/Projects/contiki TARGET=minimal-net
**
*/

#define NYOCI_INCLUDED_FROM_LIBNYOCI_H 1

#ifndef __NYOCI_HEADER__
#define __NYOCI_HEADER__ 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifndef NYOCI_CONFIG_OPTIONS_HEADER
#define NYOCI_CONFIG_OPTIONS_HEADER "nyoci-config.h"
#endif

#include NYOCI_CONFIG_OPTIONS_HEADER

#include "nyoci-helpers.h"

#include "nyoci-defaults.h"

#ifdef CONTIKI
#include "contiki.h"
#endif

#define NYOCI_CSTR_LEN     ((coap_size_t)-1)

#include "coap.h"

#include "nyoci-status.h"

/*!	@defgroup nyoci LibNyoci
**	@{
*/

NYOCI_BEGIN_C_DECLS

#if NYOCI_EMBEDDED
#define NYOCI_LIBRARY_VERSION_CHECK()	do { } while(0)
#else
#ifndef ___NYOCI_CONFIG_ID
#define ___NYOCI_CONFIG_ID 0
#endif
NYOCI_API_EXTERN void ___nyoci_check_version(uint32_t x);
#define NYOCI_LIBRARY_VERSION_CHECK()	___nyoci_check_version(___NYOCI_CONFIG_ID)
#endif

struct nyoci_s;

typedef struct nyoci_s *nyoci_t;

/*!	@addtogroup nyoci_timer
**	@{
*/

//!	Relative time period, in milliseconds.
typedef int32_t nyoci_cms_t;

//!	Absolute timestamp, platform-specific value.
typedef int32_t nyoci_timestamp_t;

//!	Special `cms` value representing the distant future.
/*!	Note that this value does not refer to a specific time. */
#define CMS_DISTANT_FUTURE		INT32_MAX

/*!	@} */

typedef nyoci_status_t (*nyoci_callback_func)(void* context);

typedef nyoci_callback_func nyoci_request_handler_func;
typedef nyoci_callback_func nyoci_inbound_resend_func;

#if NYOCI_SINGLETON
// On embedded systems, we know we will always only have
// a single nyoci instance, so we can save a considerable
// amount of stack space by simply removing the first argument
// from many functions. In order to make things as maintainable
// as possible, these macros do all of the work for us.
#define NYOCI_SINGLETON_SELF_HOOK		nyoci_t const self = nyoci_get_current_instance();(void)self
#define nyoci_init(self)		nyoci_init()
#define nyoci_release(self)		nyoci_release()
#define nyoci_get_next_msg_id(self)		nyoci_get_next_msg_id()
#define nyoci_handle_request(self,...)		nyoci_handle_request(__VA_ARGS__)
#define nyoci_handle_response(self,...)		nyoci_handle_response(__VA_ARGS__)
#define nyoci_get_timeout(self)		nyoci_get_timeout()
#define nyoci_set_proxy_url(self,...)		nyoci_set_proxy_url(__VA_ARGS__)
#define nyoci_plat_get_udp_conn(self)		nyoci_plat_get_udp_conn()
#define nyoci_handle_inbound_packet(self,...)		nyoci_handle_inbound_packet(__VA_ARGS__)
#define nyoci_outbound_begin(self,...)		nyoci_outbound_begin(__VA_ARGS__)
#define nyoci_inbound_packet_process(self,...)		nyoci_inbound_packet_process(__VA_ARGS__)
#define nyoci_vhost_add(self,...)		nyoci_vhost_add(__VA_ARGS__)
#define nyoci_set_default_request_handler(self,...)		nyoci_set_default_request_handler(__VA_ARGS__)

#define nyoci_plat_get_port(self)		nyoci_plat_get_port()
#define nyoci_plat_init(self)		nyoci_plat_init()
#define nyoci_plat_finalize(self)		nyoci_plat_finalize()
#define nyoci_plat_get_fd(self)		nyoci_plat_get_fd()
#define nyoci_plat_wait(self,...)		nyoci_plat_wait(__VA_ARGS__)
#define nyoci_plat_process(self)		nyoci_plat_process()

#define nyoci_plat_outbound_start(self,...)		nyoci_plat_outbound_start(__VA_ARGS__)
#define nyoci_plat_outbound_finish(self,...)		nyoci_plat_outbound_finish(__VA_ARGS__)
#define nyoci_plat_bind_to_port(self,...)		nyoci_plat_bind_to_port(__VA_ARGS__)
#define nyoci_plat_bind_to_sockaddr(self,...)		nyoci_plat_bind_to_sockaddr(__VA_ARGS__)


#else
#define NYOCI_SINGLETON_SELF_HOOK
#endif

NYOCI_END_C_DECLS

#include "nyoci-session.h"
#include "nyoci-plat-net.h"

NYOCI_BEGIN_C_DECLS

// MARK: -
// MARK: LibNyoci Instance Methods

/*!	@defgroup nyoci-instance Instance Methods
**	@{
**	@brief Initializing, Configuring, and Releasing the LibNyoci instance.
*/

//! Allocates and initializes an LibNyoci instance.
NYOCI_API_EXTERN nyoci_t nyoci_create(void);

//! Releases an LibNyoci instance, closing all ports and ending all transactions.
NYOCI_API_EXTERN void nyoci_release(nyoci_t self);

#if NYOCI_SINGLETON && !defined(DOXYGEN_SHOULD_SKIP_THIS)
NYOCI_API_EXTERN struct nyoci_s gNyociInstance;
#define nyoci_get_current_instance() (&gNyociInstance)
#else
//! Used from inside of callbacks to obtain a reference to the current instance.
NYOCI_API_EXTERN nyoci_t nyoci_get_current_instance(void);

#endif

//!	Sets the default request handler.
/*!	Whenever the instance receives a request that isn't
**	directed at a recognised vhost or is intended for
**	a proxy, this callback will be called.
**
**	If the inbound message is confirmable and you don't
**	end up sending a response from the callback, a
**	response packet is generated based on the return
**	value of the callback. */
NYOCI_API_EXTERN void nyoci_set_default_request_handler(
	nyoci_t self,
	nyoci_request_handler_func request_handler,
	void* context
);

#if NYOCI_CONF_ENABLE_VHOSTS
/*!	Adds a virtual host that will use the given request handler
**	instead of the default one.
**
**	This can also be used to implement groups. */
NYOCI_API_EXTERN nyoci_status_t nyoci_vhost_add(
	nyoci_t self,
	const char* name, //!^ Hostname of the virtual host
	nyoci_request_handler_func request_handler,
	void* context
);
#endif

//!	Sets the URL to use as a CoAP proxy.
/*!	The proxy is used whenever the scheme is
**	unrecognised or the host does not appear
**	to be directly reachable.
**
**	If NYOCI_AVOID_MALLOC and NYOCI_EMBEDDED are set then
**	the string IS NOT COPIED and used as is. If you
**	are building on an embedded platform, don't pass
**	in strings that are in temporary memory or that
**	live on the stack. */
NYOCI_API_EXTERN void nyoci_set_proxy_url(nyoci_t self, const char* url);

/*!	@} */

// MARK: -
// MARK: Async IO

/*!	@defgroup nyoci-asyncio Asynchronous IO
**	@{
**	@brief Functions supporting non-blocking asynchronous IO.
*/

//!	Maximum amount of time that can pass before nyoci_plat_process() must be called again.
NYOCI_API_EXTERN nyoci_cms_t nyoci_get_timeout(nyoci_t self);

/*!	@} */

// MARK: -
// MARK: Inbound Packet Interface

/*!	@defgroup nyoci-net Network Interface
**	@{
**	@brief Functions for manually handling inbound packets.
*/

#define NYOCI_INBOUND_PACKET_TRUNCATED		(1 << 0)

//! Handles an inbound packet inbound packet.
/*!	This is useful if you need direct control over the ingress
**	of traffic or want to inject packets into the CoAP stack.
**
**	Before calling this function, you *MUST* at least call the
**	function `nyoci_plat_set_remote_sockaddr()`, to set the address
**	of the sender of the packet. You can also call the following
**	functions if the default values are not appropriate:
**
**	* `nyoci_plat_set_local_sockaddr()`: If not called, uses a
**    reasonable platform-specific value.
**	* `nyoci_plat_set_session_type()`: If not called, uses the
**    value `NYOCI_SESSION_TYPE_UDP`.
**
**	If you are using BSD sockets you don't need to use this function.
**
**	Calling this function with the flag NYOCI_INBOUND_PACKET_TRUNCATED
**	will instruct the instance to not process this message and to only
**	attempt to send back a 4.13 ENTITY_TOO_LARGE response, if appropriate.
*/
NYOCI_API_EXTERN nyoci_status_t nyoci_inbound_packet_process(
	nyoci_t	self,
	char*	packet,
	coap_size_t	packet_length,
	int flags
);

//!	Handles asynchronous errors on outbound packets.
/*!	This is useful for reporting any ICMP errors
**	received back to LibNyoci so that they can be properly
**	handled.
**
**	Before calling this function, you *MUST* at least call the
**	function `nyoci_plat_set_remote_sockaddr()`, to set the address
**	of the intended destination of the packet. You can also call
**	the following function if the default values are not appropriate:
**
**	* `nyoci_plat_set_local_sockaddr()`: If not called, uses a
**    reasonable platform-specific value.
**
**	`packet` does not need to contain the entire contents
**	of the packet that generated the error. Whatever bits
**	of the packet that are given in the ICMP message will do.
**
**	If you are using BSD sockets you don't need to use this function.
*/
NYOCI_API_EXTERN void nyoci_outbound_packet_error(
	nyoci_t	self,
	const struct coap_header_s* outbound_packet_header,
	nyoci_status_t outbound_packet_error
);

/*!	@} */

// MARK: -
// MARK: Inbound Message Parsing API

/*!	@defgroup nyoci-inbound Inbound Message Parsing API
**	@{
**	@brief These functions allow callbacks to examine the
**	       current inbound packet.
**
**	Calling these functions from outside
**	of an LibNyoci callback is a runtime error.
*/

//!	Returns a pointer to the start of the current inbound CoAP packet.
NYOCI_API_EXTERN const struct coap_header_s* nyoci_inbound_get_packet(void);

//!	Returns the length of the inbound packet.
NYOCI_API_EXTERN coap_size_t nyoci_inbound_get_packet_length(void);

//! Convenience macro for getting the code of the inbound packet.
#define nyoci_inbound_get_code()		(nyoci_inbound_get_packet()->code)

//! Convenience macro for getting the msg_id of the inbound packet.
#define nyoci_inbound_get_msg_id()	(nyoci_inbound_get_packet()->msg_id)

#define NYOCI_INBOUND_FLAG_DUPE           (1<<0)
#define NYOCI_INBOUND_FLAG_MULTICAST      (1<<1)
#define NYOCI_INBOUND_FLAG_FAKE           (1<<2)
#define NYOCI_INBOUND_FLAG_HAS_OBSERVE    (1<<3)
#define NYOCI_INBOUND_FLAG_LOCAL          (1<<4)

//! Returns flags identifying status of inbound packet
NYOCI_API_EXTERN uint16_t nyoci_inbound_get_flags(void);

//! Returns true if LibNyoci thinks the inbound packet is a dupe.
#define nyoci_inbound_is_dupe() ((nyoci_inbound_get_flags()&NYOCI_INBOUND_FLAG_DUPE)==NYOCI_INBOUND_FLAG_DUPE)

//! Returns true if the inbound packet is fake (to trigger updates for observers)
#define nyoci_inbound_is_fake() ((nyoci_inbound_get_flags()&NYOCI_INBOUND_FLAG_FAKE)==NYOCI_INBOUND_FLAG_FAKE)

//! Returns true if the inbound packet is a multicast packet
#define nyoci_inbound_is_multicast() ((nyoci_inbound_get_flags()&NYOCI_INBOUND_FLAG_MULTICAST)==NYOCI_INBOUND_FLAG_MULTICAST)

//! Returns true if the inbound packet has an observe option
#define nyoci_inbound_has_observe() ((nyoci_inbound_get_flags()&NYOCI_INBOUND_FLAG_HAS_OBSERVE)==NYOCI_INBOUND_FLAG_HAS_OBSERVE)

//! Returns true if LibNyoci thinks the inbound packet originated from the local machine.
#define nyoci_inbound_is_local() ((nyoci_inbound_get_flags()&NYOCI_INBOUND_FLAG_LOCAL)==NYOCI_INBOUND_FLAG_LOCAL)

//!	Returns a pointer to the start of the inbound packet's content.
/*! Guaranteed to be NUL-terminated */
NYOCI_API_EXTERN const char* nyoci_inbound_get_content_ptr(void);

//!	Returns the length of the inbound packet's content.
NYOCI_API_EXTERN coap_size_t nyoci_inbound_get_content_len(void);

//!	Convenience function for getting the value of the observe header.
NYOCI_API_EXTERN uint32_t nyoci_inbound_get_observe(void);

//!	Convenience function for getting the content type of the inbound packet.
NYOCI_API_EXTERN coap_content_type_t nyoci_inbound_get_content_type(void);

//! Retrieve the value and type of the next option in the header and move to the next header.
NYOCI_API_EXTERN coap_option_key_t nyoci_inbound_next_option(const uint8_t** ptr, coap_size_t* len);

//! Retrieve the value and type of the next option in the header, WITHOUT moving to the next header.
NYOCI_API_EXTERN coap_option_key_t nyoci_inbound_peek_option(const uint8_t** ptr, coap_size_t* len);

//!	Reset the option pointer to the start of the options.
NYOCI_API_EXTERN void nyoci_inbound_reset_next_option(void);

//!	Compares the key and value of the current option to specific c-string values.
NYOCI_API_EXTERN bool nyoci_inbound_option_strequal(coap_option_key_t key, const char* str);

#define nyoci_inbound_option_strequal_const(key,const_str)	\
	nyoci_inbound_option_strequal(key,const_str)

#define NYOCI_GET_PATH_REMAINING			(1<<0)
#define NYOCI_GET_PATH_LEADING_SLASH		(1<<1)
#define NYOCI_GET_PATH_INCLUDE_QUERY		(1<<2)

//!	Get a string representation of the destination path in the inbound packet.
NYOCI_API_EXTERN char* nyoci_inbound_get_path(char* where, uint8_t flags);

/*!	@} */

// MARK: -
// MARK: Outbound Message Composing API

/*!	@defgroup nyoci-outbound Outbound Message Composing API
**	@{
**	@brief These functions are for constructing outbound CoAP messages from an
**	       LibNyoci callback.
**
**	Calling these functions from outside of an LibNyoci callback is an error.
*/

//!	Sets up the outbound packet as a request.
NYOCI_API_EXTERN nyoci_status_t nyoci_outbound_begin(
	nyoci_t self,
	coap_code_t code,
	coap_transaction_type_t tt
);

//! Sets up the outbound packet as a response to the current inbound packet.
/*!	This function automatically makes sure that the destination address,
**	msg_id, and token are properly set up. */
NYOCI_API_EXTERN nyoci_status_t nyoci_outbound_begin_response(coap_code_t code);

//!	Changes the code on the current outbound packet.
NYOCI_API_EXTERN nyoci_status_t nyoci_outbound_set_code(coap_code_t code);

NYOCI_API_EXTERN nyoci_status_t nyoci_set_remote_sockaddr_from_host_and_port(const char* addr_str, uint16_t toport);


//!	Adds the given option to the outbound packet.
/*!
**	Tip: If `value` is a c-string, simply pass NYOCI_CSTR_LEN
**	     as the value for `len` to avoid needing to explicitly
**	     call `strlen()`.
**
**	@note It is *much* faster to add options in numerical
**	      order than randomly. Whenever possible, add
**	      options in increasing order. */
NYOCI_API_EXTERN nyoci_status_t nyoci_outbound_add_option(
	coap_option_key_t key,
	const char* value,
	coap_size_t len
);

//!	Adds an option with a CoAP-encoded unsigned integer value.
NYOCI_API_EXTERN nyoci_status_t nyoci_outbound_add_option_uint(coap_option_key_t key, uint32_t value);

// These next four flags are for nyoci_outbound_set_uri().
#define NYOCI_MSG_SKIP_DESTADDR		(1<<0)
#define NYOCI_MSG_SKIP_AUTHORITY		(1<<1)
#define NYOCI_MSG_SKIP_PATH			(1<<2)
#define NYOCI_MSG_SKIP_QUERY			(1<<3)

//!	Sets the destination URI for the outbound packet.
/*!	If the URL is not directly reachable and a proxy URL has been
**	defined, this function will automatically use the proxy. */
NYOCI_API_EXTERN nyoci_status_t nyoci_outbound_set_uri(const char* uri, char flags);

//!	Retrieves the pointer to the content section of the outbound packet.
/*!	If you need to add content to your outbound message, call this function
**	and write your content to the location indicated by the returned pointer.
**	Do not write more than the number of bytes indicated in `max_len`.
**
**	After writing your data (or before, it doesn't really matter), use
**	nyoci_outbound_set_content_len() to indicate the length of the content.
**
**	@warning After the following function is called you cannot add any
**	         more options without losing the content. Add all of your options
**	         first! */
NYOCI_API_EXTERN char* nyoci_outbound_get_content_ptr(
	coap_size_t* max_len //^< [OUT] maximum content length
);

NYOCI_API_EXTERN coap_size_t nyoci_outbound_get_space_remaining(void);

//!	Sets the actual length of the content. Called after nyoci_outbound_get_content_ptr().
NYOCI_API_EXTERN nyoci_status_t nyoci_outbound_set_content_len(coap_size_t len);

//!	Append the given data to the end of the packet.
/*!	This function automatically updates the content length. */
NYOCI_API_EXTERN nyoci_status_t nyoci_outbound_append_content(const char* value, coap_size_t len);

//!	Append the given c-string to the end of the packet.
/*!	This function automatically updates the content length. */
#define nyoci_outbound_append_cstr(cstr)   nyoci_outbound_append_content(cstr, NYOCI_CSTR_LEN)

#if !NYOCI_AVOID_PRINTF
//!	Write to the content of the outbound message `printf` style.
NYOCI_API_EXTERN nyoci_status_t nyoci_outbound_append_content_formatted(const char* fmt, ...);

#define nyoci_outbound_append_content_formatted_const(fmt,...)	\
	nyoci_outbound_append_content_formatted(fmt,__VA_ARGS__)
#endif

//!	Sends the outbound packet.
/*!	After calling this function, you are done for this callback. You may not
**	call any other nyoci_outbound_* functions. You may only send one outbound
**	packet per callback. */
NYOCI_API_EXTERN nyoci_status_t nyoci_outbound_send(void);

//!	Convenience function to simply drop a packet.
NYOCI_API_EXTERN void nyoci_outbound_drop(void);

NYOCI_API_EXTERN void nyoci_outbound_reset(void);

//!	Sets the msg_id on the outbound packet.
/*!	@note In most cases msg_ids are handled automatically. You
**	      do not normally need to call this.
*/
NYOCI_API_EXTERN nyoci_status_t nyoci_outbound_set_msg_id(coap_msg_id_t tid);

//!	Sets the token on the outbound packet.
/*!	@note In most cases tokens are handled automatically. You
**	      do not normally need to call this.
*/
NYOCI_API_EXTERN nyoci_status_t nyoci_outbound_set_token(const uint8_t *token, uint8_t token_length);

//!	Useful for indicating errors.
NYOCI_API_EXTERN nyoci_status_t nyoci_outbound_quick_response(coap_code_t code, const char* body);

/*!	@} */

// MARK: -
// MARK: Helper Functions

NYOCI_API_EXTERN coap_msg_id_t nyoci_get_next_msg_id(nyoci_t self);

NYOCI_END_C_DECLS

/*!	@} */

#endif

#if NYOCI_DTLS
#include "nyoci-plat-tls.h"
#endif

#include "nyoci-async.h"
#include "nyoci-transaction.h"
#include "nyoci-observable.h"
#include "nyoci-helpers.h"
#include "nyoci-session.h"

#undef NYOCI_INCLUDED_FROM_LIBNYOCI_H
