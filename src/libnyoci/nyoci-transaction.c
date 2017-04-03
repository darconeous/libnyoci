/*	@file nyoci-transaction.c
**	@author Robert Quattlebaum <darco@deepdarc.com>
**	@desc Transaction functions
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

#include "assert-macros.h"
#include "libnyoci.h"
#include "nyoci-internal.h"
#include "nyoci-logging.h"
#include "nyoci-missing.h"

#if NYOCI_AVOID_MALLOC && NYOCI_TRANSACTION_POOL_SIZE
#warning Transaction pool should be moved into the LibNyoci instance.
static struct nyoci_transaction_s nyoci_transaction_pool[NYOCI_TRANSACTION_POOL_SIZE];
#endif // NYOCI_AVOID_MALLOC

#if NYOCI_TRANSACTIONS_USE_BTREE
static bt_compare_result_t
nyoci_transaction_compare(
	const void* lhs_, const void* rhs_, void* context
) {
	const nyoci_transaction_t lhs = (nyoci_transaction_t)lhs_;
	const nyoci_transaction_t rhs = (nyoci_transaction_t)rhs_;

	if (lhs->msg_id > rhs->msg_id) {
		return 1;
	}
	if (lhs->msg_id < rhs->msg_id) {
		return -1;
	}
	return 0;
}

static bt_compare_result_t
nyoci_transaction_compare_msg_id(
	const void* lhs_, const void* rhs_, void* context
) {
	const nyoci_transaction_t lhs = (nyoci_transaction_t)lhs_;
	coap_msg_id_t rhs = (coap_msg_id_t)(uintptr_t)rhs_;

	if(lhs->msg_id > rhs) {
		return 1;
	}
	if(lhs->msg_id < rhs) {
		return -1;
	}
	return 0;
}
#endif

nyoci_transaction_t
nyoci_transaction_find_via_msg_id(nyoci_t self, coap_msg_id_t msg_id) {
	NYOCI_SINGLETON_SELF_HOOK;

#if NYOCI_TRANSACTIONS_USE_BTREE
	return (nyoci_transaction_t)bt_find(
		(void*)&self->transactions,
		(void*)(uintptr_t)msg_id,
		(bt_compare_func_t)nyoci_transaction_compare_msg_id,
		self
	);
#else
	// Ouch. Linear search.
	nyoci_transaction_t ret = self->transactions;
	while(ret && (ret->msg_id != msg_id)) ret = ll_next((void*)ret);
	return ret;
#endif

}

nyoci_transaction_t
nyoci_transaction_find_via_token(nyoci_t self, coap_msg_id_t token) {
	NYOCI_SINGLETON_SELF_HOOK;

	// Ouch. Linear search.
#if NYOCI_TRANSACTIONS_USE_BTREE
	nyoci_transaction_t ret = bt_first(self->transactions);
	while(ret && (ret->token != token)) ret = bt_next(ret);
#else
	nyoci_transaction_t ret = self->transactions;
	while(ret && (ret->token != token)) ret = ll_next((void*)ret);
#endif

	return ret;
}

static void
nyoci_internal_delete_transaction_(
	nyoci_transaction_t handler,
	nyoci_t			self
) {
	DEBUG_PRINTF("nyoci_internal_delete_transaction_: %p",handler);

	if (!nyoci_get_current_instance()) {
		nyoci_set_current_instance(self);
	}

	check(self == nyoci_get_current_instance());

#if !NYOCI_TRANSACTIONS_USE_BTREE
	ll_remove((void**)&self->transactions,(void*)handler);
#endif

	// Remove the timer associated with this handler.
	nyoci_invalidate_timer(self, &handler->timer);

	handler->active = 0;

	// Fire the callback to signal that this handler is now invalidated.
	if(handler->callback) {
		(*handler->callback)(
			NYOCI_STATUS_TRANSACTION_INVALIDATED,
			handler->context
		);
	}

#if NYOCI_AVOID_MALLOC
#if NYOCI_TRANSACTION_POOL_SIZE
	if (handler->should_dealloc) {
		handler->callback = NULL;
	}
#endif
#else
	if (handler->should_dealloc) {
		free(handler);
	}
#endif
}

static nyoci_cms_t
calc_retransmit_timeout(int retries, bool burst) {
	nyoci_cms_t ret = (nyoci_cms_t)(COAP_ACK_TIMEOUT * MSEC_PER_SEC);

	if (burst) {
		if ((retries % NYOCI_TRANSACTION_BURST_COUNT) != (NYOCI_TRANSACTION_BURST_COUNT - 1)) {
			ret = NYOCI_TRANSACTION_BURST_TIMEOUT_MIN + (NYOCI_FUNC_RANDOM_UINT32() % (NYOCI_TRANSACTION_BURST_TIMEOUT_MAX-NYOCI_TRANSACTION_BURST_TIMEOUT_MIN));
			goto bail;
		}

		retries /= NYOCI_TRANSACTION_BURST_COUNT;
	}

	ret <<= retries;

	ret *= 512 + (NYOCI_FUNC_RANDOM_UINT32() % (int)(512*(COAP_ACK_RANDOM_FACTOR-1.0f)));
	ret /= 512;

bail:

#if defined(COAP_MAX_ACK_RETRANSMIT_DURATION)
	if (ret > COAP_MAX_ACK_RETRANSMIT_DURATION * MSEC_PER_SEC)
		ret = COAP_MAX_ACK_RETRANSMIT_DURATION * MSEC_PER_SEC;
#endif

	DEBUG_PRINTF("Will try attempt #%d in %dms",retries,ret);
	return ret;
}

void
nyoci_transaction_new_msg_id(
	nyoci_t			self,
	nyoci_transaction_t handler,
	coap_msg_id_t msg_id
) {
	//NYOCI_SINGLETON_SELF_HOOK;
	require(handler->active,bail);

#if NYOCI_TRANSACTIONS_USE_BTREE
	bt_remove(
		(void**)&self->transactions,
		handler,
		(bt_compare_func_t)nyoci_transaction_compare,
		(bt_delete_func_t)NULL,
		self
	);
#endif

	assert(!nyoci_transaction_find_via_msg_id(self, msg_id));

	handler->msg_id = msg_id;

#if NYOCI_TRANSACTIONS_USE_BTREE
	bt_insert(
		(void**)&self->transactions,
		handler,
		(bt_compare_func_t)nyoci_transaction_compare,
		(bt_delete_func_t)nyoci_internal_delete_transaction_,
		self
	);
#endif

bail:
	return;
}

static
bool nyoci_internal_should_burst(nyoci_transaction_t handler){
	if (handler->flags & NYOCI_TRANSACTION_BURST) {
		if (NYOCI_IS_ADDR_MULTICAST(&handler->sockaddr_remote.nyoci_addr)) {
			return NYOCI_TRANSACTION_BURST_MULTICAST == (handler->flags & NYOCI_TRANSACTION_BURST_MULTICAST);
		} else {
			return NYOCI_TRANSACTION_BURST_UNICAST == (handler->flags & NYOCI_TRANSACTION_BURST_UNICAST);
		}
	}
	return false;
}

///Checks if not reached the max attempts number yet
static
bool nyoci_internal_has_attempts(nyoci_transaction_t handler, bool should_burst){
	int max_attempts = handler->maxAttempts;

	if (should_burst) {
		max_attempts *= NYOCI_TRANSACTION_BURST_COUNT;
	}

	return handler->attemptCount < max_attempts;
}

static
nyoci_status_t nyoci_internal_resend(nyoci_t self, nyoci_transaction_t handler, nyoci_cms_t * cms, void* context)
{
	self->outbound.next_tid = handler->msg_id;
	self->is_processing_message = false;
	self->is_responding = false;
	self->did_respond = false;

	bool should_burst  = nyoci_internal_should_burst(handler);
	bool should_resend = nyoci_internal_has_attempts(handler, should_burst);

	nyoci_status_t status = NYOCI_STATUS_OK;

	if(should_resend){
		status = handler->resendCallback(context);
	}

	if (status == NYOCI_STATUS_OK && should_resend) {
		*cms = MIN(*cms, calc_retransmit_timeout(handler->attemptCount, should_burst));
		handler->attemptCount++;
	}
	else if(status == NYOCI_STATUS_STOP_RESENDING){
		//Little hack to stop sending packets (without invalidate the transaction)
		handler->attemptCount = NYOCI_TRANSACTION_MAX_ATTEMPTS;
		status = NYOCI_STATUS_OK;
	}
	else if (status == NYOCI_STATUS_WAIT_FOR_DNS || status == NYOCI_STATUS_WAIT_FOR_SESSION) {
		// TODO: Figure out a way to avoid polling?
		*cms = 100;
		status = NYOCI_STATUS_OK;
	}

	return status;
}

static void
nyoci_internal_transaction_timeout_(
	nyoci_t			self,
	nyoci_transaction_t handler
) {
	nyoci_status_t status = NYOCI_STATUS_TIMEOUT;
	void* context = handler->context;
	nyoci_cms_t cms = nyoci_plat_timestamp_to_cms(handler->expiration);

	self->current_transaction = handler;

	if ( (cms > 0)
	  || (0 == handler->attemptCount) // This makes sure we try to transmit at least once
	) {
		if ( (handler->flags & NYOCI_TRANSACTION_KEEPALIVE)
		  && (cms > NYOCI_OBSERVATION_KEEPALIVE_INTERVAL)
		) {
			cms = NYOCI_OBSERVATION_KEEPALIVE_INTERVAL;
		}

		if (cms <= 0) {
			cms = 0;
		}

		if ( (0 == handler->attemptCount)
		  && handler->waiting_for_async_response
		  && !(handler->flags&NYOCI_TRANSACTION_KEEPALIVE)
		) {
			status = NYOCI_STATUS_OK;
		}
		else if (handler->resendCallback) {
			status = nyoci_internal_resend(self, handler, &cms, context);
		}

		// Make the attempt count read at least one
		// so that we know that we have attempted to transmit
		// at least once.
		handler->attemptCount += (0 == handler->attemptCount);

		nyoci_schedule_timer(
			self,
			&handler->timer,
			cms
		);
#if NYOCI_CONF_TRANS_ENABLE_OBSERVING
	} else if((handler->flags & NYOCI_TRANSACTION_OBSERVE) != 0) {
		// We have expired and we are observing someone. In this case we
		// need to restart the observing process.

		DEBUG_PRINTF("Observe-Transaction-Timeout: Starting over for %p",handler);

		handler->waiting_for_async_response = false;
		handler->attemptCount = 0;
		handler->last_observe = 0;
#if NYOCI_CONF_TRANS_ENABLE_BLOCK2
		handler->next_block2 = 0;
#endif
		nyoci_transaction_new_msg_id(self,handler,nyoci_get_next_msg_id(self));
		handler->expiration = nyoci_plat_cms_to_timestamp(NYOCI_OBSERVATION_DEFAULT_MAX_AGE);

		if (handler->resendCallback) {
			// In this case we will be reattempting for a given duration.
			// The first attempt should happen pretty much immediately.
			cms = 0;

			if (handler->flags & NYOCI_TRANSACTION_DELAY_START) {
				// ...unless this flag is set. Then we need to wait a moment.
				cms = 10 + (NYOCI_FUNC_RANDOM_UINT32() % 290);
			}
		}

		if ( (handler->flags & NYOCI_TRANSACTION_KEEPALIVE)
		  && (cms > NYOCI_OBSERVATION_KEEPALIVE_INTERVAL)
		) {
			cms = NYOCI_OBSERVATION_KEEPALIVE_INTERVAL;
		}

		status = nyoci_schedule_timer(
			self,
			&handler->timer,
			cms
		);
#endif
	}

	if (status) {
		nyoci_response_handler_func callback = handler->callback;

#if NYOCI_CONF_TRANS_ENABLE_OBSERVING
		if(handler->flags&NYOCI_TRANSACTION_OBSERVE) {
			// If we are an observing transaction, we need to clean up
			// first by sending one last request without an observe option.
			// TODO: Implement this!
		}
#endif

		if ( !(handler->flags & NYOCI_TRANSACTION_ALWAYS_INVALIDATE)
		  && !(handler->flags & NYOCI_TRANSACTION_NO_AUTO_END)
		) {
			handler->callback = NULL;
		}

		if (callback) {
			(*callback)(status, context);
		}

		if (handler != self->current_transaction) {
			return;
		}

		if (!(handler->flags & NYOCI_TRANSACTION_NO_AUTO_END)) {
			nyoci_transaction_end(self, handler);
		}
	}

	self->current_transaction = NULL;
}


nyoci_transaction_t
nyoci_transaction_init(
	nyoci_transaction_t handler,
	int	flags,
	nyoci_inbound_resend_func resendCallback,
	nyoci_response_handler_func	callback,
	void* context
) {
	if(!handler) {
#if NYOCI_AVOID_MALLOC
#if NYOCI_TRANSACTION_POOL_SIZE
		uint8_t i;
		for (i = 0; i < NYOCI_TRANSACTION_POOL_SIZE; i++) {
			handler = &nyoci_transaction_pool[i];

			if (!handler->callback) {
				break;
			}

			handler = NULL;
		}
		if (handler) {
			handler->should_dealloc = 1;
		}
#endif
#else
		handler = (nyoci_transaction_t)calloc(sizeof(*handler), 1);
		if (handler) {
			handler->should_dealloc = 1;
		}
#endif
	} else {
		memset(handler, 0, sizeof(*handler));
	}

	require(handler!=NULL, bail);

	handler->resendCallback = resendCallback;
	handler->callback = callback;
	handler->context = context;
	handler->flags = (uint8_t)flags;
	handler->maxAttempts = NYOCI_TRANSACTION_MAX_ATTEMPTS;
bail:
	return handler;
}

nyoci_status_t
nyoci_transaction_tickle(
	nyoci_t self,
	nyoci_transaction_t handler
) {
	NYOCI_SINGLETON_SELF_HOOK;

	nyoci_invalidate_timer(self, &handler->timer);

	nyoci_schedule_timer(self,&handler->timer,0);

	return 0;
}

nyoci_status_t
nyoci_transaction_begin(
	nyoci_t self,
	nyoci_transaction_t handler,
	nyoci_cms_t expiration
) {
	nyoci_status_t ret = NYOCI_STATUS_FAILURE;
	NYOCI_SINGLETON_SELF_HOOK;

	require_action(handler != NULL, bail, ret = NYOCI_STATUS_INVALID_ARGUMENT);

	DEBUG_PRINTF("nyoci_transaction_begin: %p",handler);

#if NYOCI_TRANSACTIONS_USE_BTREE
	bt_remove(
		(void**)&self->transactions,
		(void*)handler,
		(bt_compare_func_t)nyoci_transaction_compare,
		NULL,
		self
	);
#else
	ll_remove((void**)&self->transactions,(void*)handler);
#endif

	if (expiration <= 0) {
		expiration = (nyoci_cms_t)(COAP_EXCHANGE_LIFETIME*MSEC_PER_SEC);
	}

	handler->token = nyoci_get_next_msg_id(self);
	handler->msg_id = handler->token;
	handler->waiting_for_async_response = false;
	handler->attemptCount = 0;
#if NYOCI_CONF_TRANS_ENABLE_OBSERVING
	handler->last_observe = 0;
#endif
#if NYOCI_CONF_TRANS_ENABLE_BLOCK2
	handler->next_block2 = 0;
#endif
	handler->active = 1;
	handler->expiration = nyoci_plat_cms_to_timestamp(expiration);

	if (handler->resendCallback) {
		// In this case we will be reattempting for a given duration.
		// The first attempt should happen pretty much immediately.
		expiration = 0;

		if (handler->flags & NYOCI_TRANSACTION_DELAY_START) {
			// Unless this flag is set. Then we need to wait a moment.
			expiration = 10 + (NYOCI_FUNC_RANDOM_UINT32() % (MSEC_PER_SEC*COAP_DEFAULT_LEASURE));
		}
	}

	if ( (handler->flags & NYOCI_TRANSACTION_KEEPALIVE)
	  && (expiration > NYOCI_OBSERVATION_KEEPALIVE_INTERVAL)
	) {
		expiration = NYOCI_OBSERVATION_KEEPALIVE_INTERVAL;
	}

	ret = nyoci_schedule_timer(
		self,
		nyoci_timer_init(
			&handler->timer,
			(nyoci_timer_callback_t)&nyoci_internal_transaction_timeout_,
			NULL,
			handler
		),
		expiration
	);

	require_noerr(ret, bail);

#if NYOCI_TRANSACTIONS_USE_BTREE
	bt_insert(
		(void**)&self->transactions,
		handler,
		(bt_compare_func_t)nyoci_transaction_compare,
		(bt_delete_func_t)nyoci_internal_delete_transaction_,
		self
	);
	DEBUG_PRINTF(CSTR("%p: Total Pending Transactions: %d"), self,
		(int)bt_count((void**)&self->transactions));
#else
	ll_prepend((void**)&self->transactions,(void*)handler);
	DEBUG_PRINTF(CSTR("%p: Total Pending Transactions: %d"), self,
		(int)ll_count((void**)&self->transactions));
#endif

	ret = NYOCI_STATUS_OK;

bail:
	return ret;
}

nyoci_status_t
nyoci_transaction_end(
	nyoci_t self,
	nyoci_transaction_t transaction
) {
	NYOCI_SINGLETON_SELF_HOOK;
	DEBUG_PRINTF("nyoci_transaction_end: %p",transaction);

	check(transaction->active);

	if (!transaction->active) {
		return NYOCI_STATUS_INVALID_ARGUMENT;
	}

#if NYOCI_CONF_TRANS_ENABLE_OBSERVING
	if (transaction->flags & NYOCI_TRANSACTION_OBSERVE) {
		// If we are an observing transaction, we need to clean up
		// first by sending one last request without an observe option.
		// TODO: Implement this!
	}
#endif

	if (transaction == self->current_transaction) {
		self->current_transaction = NULL;
	}

	if (transaction->active) {
#if NYOCI_TRANSACTIONS_USE_BTREE
		bt_remove(
			(void**)&self->transactions,
			(void*)transaction,
			(bt_compare_func_t)nyoci_transaction_compare,
			(bt_delete_func_t)nyoci_internal_delete_transaction_,
			self
		);
#else
		ll_remove((void**)&self->transactions,(void*)transaction);
		nyoci_internal_delete_transaction_(transaction,self);
#endif
	}
	return NYOCI_STATUS_OK;
}


static nyoci_transaction_t
lookup_transaction_(const struct coap_header_s* packet)
{
	nyoci_t const self = nyoci_get_current_instance();
	nyoci_transaction_t handler = NULL;
	coap_msg_id_t token = 0;

	if(self->inbound.packet->token_len == sizeof(coap_msg_id_t)) {
		memcpy(&token,self->inbound.packet->token,sizeof(token));
	}

	handler = nyoci_transaction_find_via_msg_id(self, packet->msg_id);

	if (NULL == handler) {
		if (self->inbound.packet->tt < COAP_TRANS_TYPE_ACK) {
			handler = nyoci_transaction_find_via_token(self,token);
		}
	} else if (nyoci_inbound_get_packet()->code != COAP_CODE_EMPTY
		&& token != handler->token
	) {
		handler = NULL;
	}

	if ( handler
	  && !handler->multicast
	  && ( (0 != memcmp(&handler->sockaddr_remote.nyoci_addr, &nyoci_plat_get_remote_sockaddr()->nyoci_addr, sizeof(nyoci_addr_t)))
		|| (handler->sockaddr_remote.nyoci_port != nyoci_plat_get_remote_sockaddr()->nyoci_port)
	  )
	) {
		// Message-ID or token matched, but the address didn't. Fail.
		DEBUG_PRINTF("Remote address doesn't match transaction, fail.");
		handler = NULL;
	}

	return handler;
}

void
nyoci_outbound_packet_error(
	nyoci_t	self,
	const struct coap_header_s* outbound_packet_header,
	nyoci_status_t outbound_packet_error
) {
	nyoci_transaction_t handler;
	nyoci_status_t status;
	coap_msg_id_t msg_id = nyoci_inbound_get_msg_id();

	nyoci_set_current_instance(self);

	check(outbound_packet_error < 0);

	if (outbound_packet_error >= 0) {
		outbound_packet_error = NYOCI_STATUS_FAILURE;
	}

	handler = lookup_transaction_(outbound_packet_header);

	require(handler != NULL, bail);

	nyoci_response_handler_func callback = handler->callback;

	if ( !(handler->flags & NYOCI_TRANSACTION_ALWAYS_INVALIDATE)
	  && !(handler->flags & NYOCI_TRANSACTION_OBSERVE)
	) {
		handler->callback = NULL;
	}

	status = (*callback)(
		outbound_packet_error,
		handler->context
	);

	check_noerr(status);

	// If self->current_transaction is NULL at this point,
	// then that means that the transaction has been
	// finalized and we shouldn't continue.
	if (self->current_transaction != handler) {
		goto bail;
	}

	// TODO: Explain why this is necessary
	// Can't remember what I was thinking at the time.
	// I think this is to head off additional processing
	// if the handler ended up manipulating the transaction.
	if (msg_id != handler->msg_id) {
		goto bail;
	}

	handler->attemptCount = 0;
	handler->waiting_for_async_response = false;

#if NYOCI_CONF_TRANS_ENABLE_OBSERVING
	if ( status == NYOCI_STATUS_OK
	  && (handler->flags & NYOCI_TRANSACTION_OBSERVE)
	) {
		nyoci_cms_t cms = self->inbound.max_age * MSEC_PER_SEC;

#if NYOCI_CONF_TRANS_ENABLE_BLOCK2
		handler->next_block2 = 0;
#endif // NYOCI_CONF_TRANS_ENABLE_BLOCK2

		nyoci_invalidate_timer(self, &handler->timer);

		if (0 == cms) {
			if (self->inbound.flags & NYOCI_INBOUND_FLAG_HAS_OBSERVE) {
				cms = CMS_DISTANT_FUTURE;
			} else {
				cms = NYOCI_OBSERVATION_DEFAULT_MAX_AGE;
			}
		}

		handler->expiration = nyoci_plat_cms_to_timestamp(cms);

		if ( (handler->flags & NYOCI_TRANSACTION_KEEPALIVE)
		  && (cms > NYOCI_OBSERVATION_KEEPALIVE_INTERVAL)
		) {
			cms = NYOCI_OBSERVATION_KEEPALIVE_INTERVAL;
		}

		nyoci_schedule_timer(
			self,
			&handler->timer,
			cms
		);
	} else
#endif // #if NYOCI_CONF_TRANS_ENABLE_OBSERVING
	{
		handler->resendCallback = NULL;
		if (!(handler->flags & NYOCI_TRANSACTION_NO_AUTO_END)) {
			nyoci_transaction_end(self, handler);
		}
	}

bail:
	return;
}

nyoci_status_t
nyoci_handle_response() {
	nyoci_status_t ret = 0;
	nyoci_t const self = nyoci_get_current_instance();
	nyoci_transaction_t handler = NULL;
	coap_msg_id_t msg_id = nyoci_inbound_get_msg_id();
	bool request_was_multicast = false;

#if VERBOSE_DEBUG
	DEBUG_PRINTF(
		"nyoci(%p): Incoming response! msgid=0x%02X",
		self,
		msg_id
	);
#if NYOCI_TRANSACTIONS_USE_BTREE
	DEBUG_PRINTF("%p: Total Pending Transactions: %d", self,
		(int)bt_count((void**)&self->transactions));
#else
	DEBUG_PRINTF("%p: Total Pending Transactions: %d", self,
		(int)ll_count((void**)&self->transactions));
#endif
#endif // VERBOSE_DEBUG

	handler = lookup_transaction_(self->inbound.packet);

	self->current_transaction = handler;

	if (handler == NULL) {
		// This is an unknown response. If the packet
		// is confirmable, send a reset. If not, don't bother.
		if(self->inbound.packet->tt <= COAP_TRANS_TYPE_NONCONFIRMABLE) {
			DEBUG_PRINTF("Inbound: Unknown Response, sending reset. . .");

			nyoci_outbound_begin_response(0);
			self->outbound.packet->tt = COAP_TRANS_TYPE_RESET;
			ret = nyoci_outbound_send();
		} else {
			DEBUG_PRINTF("Inbound: Unknown ack or reset, ignoring. . .");
		}
	} else if ( ( (self->inbound.packet->tt == COAP_TRANS_TYPE_ACK)
			   || (self->inbound.packet->tt == COAP_TRANS_TYPE_NONCONFIRMABLE)
			  )
			 && (self->inbound.packet->code == COAP_CODE_EMPTY)
			 && (handler->sent_code < COAP_RESULT_100)
	) {
		DEBUG_PRINTF("Inbound: Empty ACK, Async response expected.");
		handler->waiting_for_async_response = true;
	} else if(handler->callback) {
		msg_id = handler->msg_id;
		request_was_multicast = NYOCI_IS_ADDR_MULTICAST(&handler->sockaddr_remote.nyoci_addr);

		DEBUG_PRINTF("Inbound: Transaction handling response.");

		nyoci_inbound_reset_next_option();

#if NYOCI_CONF_TRANS_ENABLE_OBSERVING
		if ( (handler->flags & NYOCI_TRANSACTION_OBSERVE)
		  && (self->inbound.flags & NYOCI_INBOUND_FLAG_HAS_OBSERVE)
		) {
			nyoci_cms_t cms = self->inbound.max_age * MSEC_PER_SEC;

			if ( (self->inbound.flags & NYOCI_INBOUND_FLAG_HAS_OBSERVE)
			  && (self->inbound.observe_value <= handler->last_observe)
			  && ((handler->last_observe - self->inbound.observe_value) > 0x7FFFFF)
			) {
				DEBUG_PRINTF("Inbound: Skipping older inbound observation. (%d<=%d)",self->inbound.observe_value,handler->last_observe);
				// We've already seen this one. Skip it.
				ret = NYOCI_STATUS_DUPE;
				goto bail;
			}

			handler->last_observe = self->inbound.observe_value;

			ret = (*handler->callback)(
				self->inbound.packet->tt==COAP_TRANS_TYPE_RESET?NYOCI_STATUS_RESET:self->inbound.packet->code,
				handler->context
			);

			check_noerr(ret);

			// If self->current_transaction is NULL at this point,
			// then that means that the transaction has been
			// finalized and we shouldn't continue.
			if (!self->current_transaction) {
				handler = NULL;
				goto bail;
			}

			// TODO: Explain why this is necessary
			// Can't remember what I was thinking at the time.
			// I think this is to head off additional processing
			// if the handler ended up manipulating the transaction.
			if (msg_id != handler->msg_id) {
				handler = NULL;
				goto bail;
			}

			handler->attemptCount = 0;
			handler->timer.cancel = NULL;

#if NYOCI_CONF_TRANS_ENABLE_BLOCK2
			if ( !ret
			  && (self->inbound.block2_value&(1<<3))
			  && (handler->flags&NYOCI_TRANSACTION_ALWAYS_INVALIDATE)
			) {
				DEBUG_PRINTF("Inbound: Preparing to request next block...");
				handler->waiting_for_async_response = false;
				handler->next_block2 = self->inbound.block2_value + (1<<4);
				nyoci_transaction_new_msg_id(self, handler, nyoci_get_next_msg_id(self));
				nyoci_invalidate_timer(self, &handler->timer);
				nyoci_schedule_timer(
					self,
					&handler->timer,
					0
				);
				goto bail;
			} else
#endif
			if (self->inbound.flags & NYOCI_INBOUND_FLAG_HAS_OBSERVE) {
				handler->waiting_for_async_response = true;
			}

			if(!cms) {
				if (self->inbound.flags & NYOCI_INBOUND_FLAG_HAS_OBSERVE) {
					cms = CMS_DISTANT_FUTURE;
				} else {
					cms = NYOCI_OBSERVATION_DEFAULT_MAX_AGE;
				}
			}

			handler->expiration = nyoci_plat_cms_to_timestamp(cms);

			if(	(handler->flags&NYOCI_TRANSACTION_KEEPALIVE)
				&& cms>NYOCI_OBSERVATION_KEEPALIVE_INTERVAL
			) {
				cms = NYOCI_OBSERVATION_KEEPALIVE_INTERVAL;
			}

			nyoci_schedule_timer(
				self,
				&handler->timer,
				cms
			);

		} else
#endif // #if NYOCI_CONF_TRANS_ENABLE_OBSERVING
		{
			nyoci_response_handler_func callback = handler->callback;

			if ( !(handler->flags & NYOCI_TRANSACTION_ALWAYS_INVALIDATE)
			  && !(handler->flags & NYOCI_TRANSACTION_OBSERVE)
			  && !(handler->flags & NYOCI_TRANSACTION_NO_AUTO_END)
			  && !request_was_multicast
			) {
				// TODO: Add a flag instead of setting this to NULL.
				handler->callback = NULL;
			}

			ret = (*callback)(
				(self->inbound.packet->tt==COAP_TRANS_TYPE_RESET)?NYOCI_STATUS_RESET:self->inbound.packet->code,
				handler->context
			);

			check_noerr(ret);

			// If self->current_transaction is NULL at this point,
			// then that means that the transaction has been
			// finalized and we shouldn't continue.

			if (self->current_transaction != handler) {
				handler = NULL;
				goto bail;
			}

			// TODO: Explain why this is necessary
			// Can't remember what I was thinking at the time.
			// I think this is to head off additional processing
			// if the handler ended up manipulating the transaction.
			if (msg_id != handler->msg_id) {
				handler = NULL;
				goto bail;
			}

			if (!request_was_multicast) {
				handler->attemptCount = 0;
			}

			handler->waiting_for_async_response = false;

			if ( handler->active
			  && msg_id == handler->msg_id
			) {
#if NYOCI_CONF_TRANS_ENABLE_BLOCK2
				if(!ret && (self->inbound.block2_value&(1<<3)) && (handler->flags&NYOCI_TRANSACTION_ALWAYS_INVALIDATE)) {
					DEBUG_PRINTF("Inbound: Preparing to request next block...");
					handler->next_block2 = self->inbound.block2_value + (1<<4);
					nyoci_transaction_new_msg_id(self, handler, nyoci_get_next_msg_id(self));
					nyoci_invalidate_timer(self, &handler->timer);
					nyoci_schedule_timer(
						self,
						&handler->timer,
						0
					);
				} else
#endif // NYOCI_CONF_TRANS_ENABLE_BLOCK2
#if NYOCI_CONF_TRANS_ENABLE_OBSERVING
				if (!ret && (handler->flags & NYOCI_TRANSACTION_OBSERVE)) {
					nyoci_cms_t cms = self->inbound.max_age*1000;
#if NYOCI_CONF_TRANS_ENABLE_BLOCK2
					handler->next_block2 = 0;
#endif // NYOCI_CONF_TRANS_ENABLE_BLOCK2

					nyoci_invalidate_timer(self, &handler->timer);

					if (!cms) {
						if (self->inbound.flags & NYOCI_INBOUND_FLAG_HAS_OBSERVE) {
							cms = CMS_DISTANT_FUTURE;
						} else {
							cms = NYOCI_OBSERVATION_DEFAULT_MAX_AGE;
						}
					}

					handler->expiration = nyoci_plat_cms_to_timestamp(cms);

					if(	(handler->flags&NYOCI_TRANSACTION_KEEPALIVE)
						&& cms>NYOCI_OBSERVATION_KEEPALIVE_INTERVAL
					) {
						cms = NYOCI_OBSERVATION_KEEPALIVE_INTERVAL;
					}

					nyoci_schedule_timer(
						self,
						&handler->timer,
						cms
					);
				} else
#endif // #if NYOCI_CONF_TRANS_ENABLE_OBSERVING
				{
					if (!request_was_multicast) {
						// TODO: Add a flag instead of setting this to NULL.
						handler->resendCallback = NULL;
					}
					if (!(handler->flags & NYOCI_TRANSACTION_NO_AUTO_END)) {
						nyoci_transaction_end(self, handler);
					}
					handler = NULL;
				}
			}
		}
	}

bail:
	if ( (ret != NYOCI_STATUS_OK)
	  && (handler != NULL)
	  && !(handler->flags & NYOCI_TRANSACTION_NO_AUTO_END)
	) {
		nyoci_transaction_end(self, handler);
	}
	return ret;
}
