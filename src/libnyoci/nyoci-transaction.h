/*!	@file nyoci-transaction.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
**	@brief Transaction functions
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

#ifndef __NYOCI_TRANSACTION_H__
#define __NYOCI_TRANSACTION_H__

#if !defined(NYOCI_INCLUDED_FROM_LIBNYOCI_H) && !defined(BUILDING_LIBNYOCI)
#error "Do not include this header directly, include <libnyoci/libnyoci.h> instead"
#endif

#include "nyoci-timer.h"

#if NYOCI_TRANSACTIONS_USE_BTREE
#include "btree.h"
#else
#include "ll.h"
#endif

#if NYOCI_SINGLETON
// On embedded systems, we know we will always only have
// a single nyoci instance, so we can save a considerable
// amount of stack spaces by simply removing the first argument
// from many functions. In order to make things as maintainable
// as possible, these macros do all of the work for us.
#define nyoci_transaction_find_via_msg_id(self,...)		nyoci_transaction_find_via_msg_id(__VA_ARGS__)
#define nyoci_transaction_find_via_token(self,...)		nyoci_transaction_find_via_token(__VA_ARGS__)
#define nyoci_transaction_begin(self,...)		nyoci_transaction_begin(__VA_ARGS__)
#define nyoci_transaction_end(self,...)		nyoci_transaction_end(__VA_ARGS__)
#define nyoci_transaction_new_msg_id(self,...)		nyoci_transaction_new_msg_id(__VA_ARGS__)
#define nyoci_transaction_tickle(self,...)		nyoci_transaction_tickle(__VA_ARGS__)
#endif

#define NYOCI_TRANSACTION_MAX_ATTEMPTS	15

NYOCI_BEGIN_C_DECLS
/*!	@addtogroup nyoci
**	@{
*/

//struct nyoci_session_s;
//
/*!	@defgroup nyoci_trans Transaction API
**	@{
*/

/*! Returning pretty much anything here except NYOCI_STATUS_OK will
**	cause the handler to invalidate. */
typedef nyoci_status_t (*nyoci_response_handler_func)(
	int statuscode,
	void* context
);

struct nyoci_transaction_s {
#if NYOCI_TRANSACTIONS_USE_BTREE
	struct bt_item_s			bt_item;
#else
	struct ll_item_s			ll_item;
#endif

	nyoci_inbound_resend_func	resendCallback;
	nyoci_response_handler_func	callback;
	void*						context;

	// This expiration field has different meaning depending on
	// if this is an observable transaction or not. If it is
	// not observable, the expiration is when the transaction should
	// be "timed out". If it is observable, it is when the
	// max-age expires and we need to restart observing.
	nyoci_timestamp_t			expiration;
	struct nyoci_timer_s			timer;

	coap_msg_id_t				token;
	coap_msg_id_t				msg_id;
	nyoci_sockaddr_t				sockaddr_remote;

#if NYOCI_CONF_TRANS_ENABLE_OBSERVING
	uint32_t					last_observe;
#endif

#if NYOCI_CONF_TRANS_ENABLE_BLOCK2
	uint32_t					next_block2;
#endif

	coap_code_t					sent_code;

	uint8_t						flags;
	uint8_t						attemptCount:4, maxAttempts:4,
								waiting_for_async_response:1,
								should_dealloc:1,
								active:1,
								needs_to_close_observe:1,
								multicast:1;
};

typedef struct nyoci_transaction_s* nyoci_transaction_t;

enum {
	//! Always call callback with NYOCI_STATUS_INVALIDATE when invalidating the transaction.
	/*! In a normal unicast transaction, there is always
	 *  exactly one call to the `callback` function, so
	 *  it is not ambiguous if the transaction has been
	 *  invalidated or not. However, certain transactions
	 *  can have multiple calls to `callback`, so it can
	 *  be ambiguous if the transaction has been invalidated
	 *  or not. When this flag is present, the transaction
	 *  callback will ALWAYS be called with a status of
	 *  `NYOCI_STATUS_INVALIDATE` when the transaction is
	 *  invalidated. */
	NYOCI_TRANSACTION_ALWAYS_INVALIDATE = (1 << 0),

	NYOCI_TRANSACTION_OBSERVE = (1 << 1),

	NYOCI_TRANSACTION_KEEPALIVE = (1 << 2),		//!< Send keep-alive packets when observing

	NYOCI_TRANSACTION_NO_AUTO_END = (1 << 3),

	NYOCI_TRANSACTION_BURST_UNICAST = (1 << 4), //!< Burst multiple unicast packets per retransmit
	NYOCI_TRANSACTION_BURST_MULTICAST = (1 << 5), //!< Burst multiple multicast packets per retransmit

	NYOCI_TRANSACTION_BURST = NYOCI_TRANSACTION_BURST_UNICAST|NYOCI_TRANSACTION_BURST_MULTICAST, //!< Burst multiple packets per retransmit

	NYOCI_TRANSACTION_DELAY_START = (1 << 8),
};

//!	Initialize the given transaction object.
NYOCI_API_EXTERN nyoci_transaction_t nyoci_transaction_init(
	nyoci_transaction_t transaction,
	int	flags,
	nyoci_inbound_resend_func requestResend,
	nyoci_response_handler_func responseHandler,
	void* context
);

NYOCI_API_EXTERN nyoci_status_t nyoci_transaction_begin(
	nyoci_t self,
	nyoci_transaction_t transaction,
	nyoci_cms_t expiration
);

//!	Explicitly terminate this transaction.
NYOCI_API_EXTERN nyoci_status_t nyoci_transaction_end(
	nyoci_t self,
	nyoci_transaction_t transaction
);

//!	Force a transaction to retry/retransmit
NYOCI_API_EXTERN nyoci_status_t nyoci_transaction_tickle(
	nyoci_t self,
	nyoci_transaction_t transaction
);

//!	Change the message id on the given transaction.
/*!	Does not change the token. This is used when you
**	want to use the same transaction object to handle
**	a series of message requests and responses.
**	For example, this is used for observation and block
**	transfers. */
NYOCI_API_EXTERN void nyoci_transaction_new_msg_id(
	nyoci_t			self,
	nyoci_transaction_t handler,
	coap_msg_id_t msg_id
);

/*!	@} */
/*!	@} */

NYOCI_END_C_DECLS

#endif
