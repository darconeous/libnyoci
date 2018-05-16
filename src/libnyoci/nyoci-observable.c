/*	@file nyoci-observable.c
**	@author Robert Quattlebaum <darco@deepdarc.com>
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
#include "nyoci-internal.h"
#include "nyoci-logging.h"

#define INVALID_OBSERVER_INDEX		(NYOCI_MAX_OBSERVERS)

#if NYOCI_MAX_OBSERVERS > 127
#error "NYOCI_MAX_OBSERVERS must be set below 127"
#endif

#define SHOULD_CONFIRM_EVENT_FOR_OBSERVER(obs)		should_confirm_event_for_observer(obs)

struct nyoci_observer_s {
	/**** All of this is private. Don't touch. ****/

	struct nyoci_observable_s *observable;
	int8_t next;	// always n+1, zero is end of list
	uint8_t key;
	bool on_hold:1;   // Set when we are waiting for a response to a CON
	uint32_t seq;
	struct nyoci_async_response_s async_response;
	struct nyoci_transaction_s transaction;
};

// TODO: We really need to move the observer table into the nyoci_t instance.
// Note that this doesn't really matter for embedded systems, but on
// multi-threaded systems with multiple nyoci instances, this is going to
// fail.
static struct nyoci_observer_s observer_table[NYOCI_MAX_OBSERVERS];

static bool
should_confirm_event_for_observer(const struct nyoci_observer_s* obs) {
	return obs->on_hold || !((obs)->seq&0x7);
}

static int8_t
get_unused_observer_index() {
	int8_t ret = 0;
	for (; ret < NYOCI_MAX_OBSERVERS; ret++) {
		const struct nyoci_observer_s * const obs = &observer_table[ret];
		if ( obs->async_response.request_len == 0
		  && obs->next == 0
		  && obs->transaction.active == 0
		) {
			break;
		}
	}
	if (ret == NYOCI_MAX_OBSERVERS) {
		ret = -1;
	}
	return ret;
}

static void
free_observer(struct nyoci_observer_s *observer)
{
	nyoci_observable_t const context = observer->observable;
	int8_t i = (int8_t)(observer - observer_table);

#if !NYOCI_SINGLETON
	if (!observer->observable) {
		goto bail;
	}
	nyoci_t const interface = observer->observable->interface;
#endif

	nyoci_transaction_end(interface, &observer->transaction);

	if ((context->first_observer==i+1) && (context->last_observer==i+1)) {
		context->first_observer = context->last_observer = 0;

	} else if (context->first_observer == i+1) {
		context->first_observer = observer_table[i].next;

	} else {
		int8_t prev;
		for (prev = context->first_observer-1; prev>=0; i = observer_table[i].next - 1) {
			if (observer_table[prev].next == i) {
				break;
			}
		}

		observer_table[prev].next = observer_table[i].next;

		if (context->last_observer == i+1) {
			context->last_observer = prev;
		}
	}

bail:
	observer->observable = NULL;
	observer->next = 0;
	nyoci_finish_async_response(&observer->async_response);
	return;
}

nyoci_status_t
nyoci_observable_update(nyoci_observable_t context, uint8_t key) {
	nyoci_status_t ret = NYOCI_STATUS_OK;
	nyoci_t const interface = nyoci_get_current_instance();
	int8_t i;

#if !NYOCI_SINGLETON
	context->interface = interface;
#endif

	if ( (interface->inbound.packet == NULL)
	  || (interface->inbound.flags & (NYOCI_INBOUND_FLAG_FAKE|NYOCI_INBOUND_FLAG_DUPE)) != 0
	  || (nyoci_inbound_get_code() != COAP_METHOD_GET)
	) {
		goto bail;
	}

	for (i = context->first_observer-1; i >= 0; i = observer_table[i].next - 1) {
		assert(observer_table[i].observable == context);
		if (observer_table[i].key != key) {
			continue;
		}
		if (nyoci_inbound_is_related_to_async_response(&observer_table[i].async_response)) {
			break;
		}
	}

	if (interface->inbound.flags & NYOCI_INBOUND_FLAG_HAS_OBSERVE) {
		if (i == -1) {
			i = get_unused_observer_index();

			if (i == -1) {
				goto bail;
			}

			if (context->last_observer == 0) {
				context->first_observer = context->last_observer = i + 1;
			} else {
				observer_table[context->last_observer-1].next = i +1;
				context->last_observer = i + 1;
			}

			observer_table[i].key = key;
			observer_table[i].seq = 0;
			observer_table[i].observable = context;
			observer_table[i].on_hold = false;
		}

		require_noerr_action(
			ret = nyoci_start_async_response(
				&observer_table[i].async_response,
				NYOCI_ASYNC_RESPONSE_FLAG_DONT_ACK
			),
			bail,
			free_observer(&observer_table[i])
		);

		require_noerr_action(
			ret = nyoci_outbound_add_option_uint(COAP_OPTION_OBSERVE, observer_table[i].seq),
			bail,
			free_observer(&observer_table[i])
		);

	} else if (i != -1) {
		free_observer(&observer_table[i]);
	}

bail:
	return ret;
}

static nyoci_status_t
event_response_handler(int statuscode, struct nyoci_observer_s* observer)
{
	if (statuscode >= 0) {
		observer->on_hold = false;
	}

	if (statuscode == NYOCI_STATUS_TIMEOUT) {
		if (SHOULD_CONFIRM_EVENT_FOR_OBSERVER(observer)) {
			statuscode = NYOCI_STATUS_RESET;
		} else {
			statuscode = NYOCI_STATUS_OK;
		}
	}

	if (statuscode != NYOCI_STATUS_TRANSACTION_INVALIDATED) {
		if ( (statuscode != 0)
		  && ( (statuscode <  COAP_RESULT_200)
			|| (statuscode >= COAP_RESULT_400)
		  )
		) {
			statuscode = NYOCI_STATUS_RESET;
		}
	}

	if (statuscode == NYOCI_STATUS_RESET) {
		free_observer(observer);
		return NYOCI_STATUS_RESET;
	}

	return NYOCI_STATUS_OK;
}

static nyoci_status_t
retry_sending_event(struct nyoci_observer_s* observer)
{
	nyoci_status_t status;
	nyoci_t const self = nyoci_get_current_instance();

	status = nyoci_outbound_begin_async_response(COAP_RESULT_205_CONTENT, &observer->async_response);
	require_noerr(status,bail);

	status = nyoci_outbound_add_option_uint(COAP_OPTION_OBSERVE, observer->seq);
	require_noerr(status,bail);

	self->outbound.packet->tt = SHOULD_CONFIRM_EVENT_FOR_OBSERVER(observer)
		? COAP_TRANS_TYPE_CONFIRMABLE
		: COAP_TRANS_TYPE_NONCONFIRMABLE;

	self->inbound.flags |= NYOCI_INBOUND_FLAG_HAS_OBSERVE;
	self->is_responding = true;
	self->force_current_outbound_code = true;
	self->is_processing_message = true;
	self->did_respond = false;

#if VERBOSE_DEBUG
	coap_dump_header(
		NYOCI_DEBUG_OUT_FILE,
		"FAKE Inbound:\t",
		self->inbound.packet,
		self->inbound.packet_len
	);
#endif

	status = nyoci_handle_request();
	require(!status || status == NYOCI_STATUS_NOT_FOUND || status == NYOCI_STATUS_NOT_ALLOWED, bail);

	if (status) {
		nyoci_outbound_set_content_len(0);
		nyoci_outbound_send();
	}

bail:
	self->is_processing_message = false;
	self->did_respond = false;
	return status;
}

static nyoci_status_t
trigger_observer(nyoci_t interface, struct nyoci_observer_s* observer, int flags)
{
	nyoci_status_t ret = NYOCI_STATUS_OK;
	const bool force_con = ((flags & NYOCI_OBS_TRIGGER_FLAG_FORCE_CON) == NYOCI_OBS_TRIGGER_FLAG_FORCE_CON);

	if ((flags & NYOCI_OBS_TRIGGER_FLAG_NO_INCREMENT) != NYOCI_OBS_TRIGGER_FLAG_NO_INCREMENT) {
		observer->seq++;
	}

	// If we are about to need confirmation, then
	// clear out the previous transaction so we can
	// continue;
	if (!observer->on_hold && SHOULD_CONFIRM_EVENT_FOR_OBSERVER(observer)) {
		nyoci_transaction_end(interface, &observer->transaction);
	}

	if (observer->transaction.active) {
		// The transaction is still active, so just tickle it.

		if (!observer->on_hold) {
			nyoci_transaction_new_msg_id(interface, &observer->transaction, nyoci_get_next_msg_id(interface));
		}

		nyoci_transaction_tickle(interface, &observer->transaction);
	} else {
		bool should_confirm = force_con || SHOULD_CONFIRM_EVENT_FOR_OBSERVER(observer);
		observer->on_hold |= should_confirm;

		nyoci_transaction_init(
			&observer->transaction,
			0, // Flags
			(void*)&retry_sending_event,
			(void*)&event_response_handler,
			(void*)observer
		);

		ret = nyoci_transaction_begin(
			interface,
			&observer->transaction,
			should_confirm?NYOCI_OBSERVER_CON_EVENT_EXPIRATION:NYOCI_OBSERVER_NON_EVENT_EXPIRATION
		);
	}

	return ret;
}

int
nyoci_count_observers(nyoci_t interface)
{
	int ret = 0;
	int8_t i = 0;

	for (; i < NYOCI_MAX_OBSERVERS; i++) {
		struct nyoci_observer_s* observer = &observer_table[i];

		if ( (observer->next != 0)
		  && (observer->observable != NULL)
#if !NYOCI_SINGLETON
		  && (observer->observable->interface == interface)
#endif
		) {
			ret++;
		}
	}
	return ret;
}

void
nyoci_refresh_observers(nyoci_t interface, uint8_t flags)
{
	int8_t i = 0;
	for (; i < NYOCI_MAX_OBSERVERS; i++) {
		struct nyoci_observer_s* observer = &observer_table[i];
		if ( (observer->next != 0)
		  && (observer->observable != NULL)
#if !NYOCI_SINGLETON
		  && (observer->observable->interface == interface)
#endif
		) {
			trigger_observer(interface, observer, flags);
		}
	}
}

nyoci_status_t
nyoci_observable_trigger(nyoci_observable_t context, uint8_t key, uint8_t flags)
{
	nyoci_status_t ret = NYOCI_STATUS_OK;
	int8_t i;
#if !NYOCI_SINGLETON
	nyoci_t const interface = context->interface;

	if (!interface) {
		goto bail;
	}
#else
	nyoci_t const interface = nyoci_get_current_instance();
#endif


	if (!context->first_observer) {
		goto bail;
	}

	for (i = context->first_observer-1; i >= 0; i = observer_table[i].next - 1) {
		assert(observer_table[i].observable == context);
		assert((i != context->last_observer-1) || observer_table[i].next == 0);

		if ((observer_table[i].key != NYOCI_OBSERVABLE_BROADCAST_KEY)
			&& (key != NYOCI_OBSERVABLE_BROADCAST_KEY)
			&& (observer_table[i].key != key)
		) {
			continue;
		}
		ret = trigger_observer(interface, &observer_table[i], flags);
	}

bail:
	return ret;
}

int
nyoci_observable_observer_count(nyoci_observable_t context, uint8_t key)
{
	int count = 0;
	int i;

	if (!context->first_observer) {
		goto bail;
	}

	for (i = context->first_observer-1; i >= 0; i = observer_table[i].next - 1) {
		assert(observer_table[i].observable == context);
		assert((i != context->last_observer-1) || observer_table[i].next == 0);

		if ((observer_table[i].key != NYOCI_OBSERVABLE_BROADCAST_KEY)
			&& (key != NYOCI_OBSERVABLE_BROADCAST_KEY)
			&& (observer_table[i].key != key)
		) {
			continue;
		}
		count++;
	}

bail:
	return count;
}

int
nyoci_observable_clear(
	nyoci_observable_t context,
	uint8_t key
) {
	int count = 0;
	int i;

	if (!context->first_observer) {
		goto bail;
	}

restart:

	for (i = context->first_observer-1; i >= 0; i = observer_table[i].next - 1) {
		assert(observer_table[i].observable == context);
		assert((i != context->last_observer-1) || observer_table[i].next == 0);

		if ((observer_table[i].key != NYOCI_OBSERVABLE_BROADCAST_KEY)
			&& (key != NYOCI_OBSERVABLE_BROADCAST_KEY)
			&& (observer_table[i].key != key)
		) {
			continue;
		}
		count++;
		free_observer(&observer_table[i]);

		// Since we mutated the list, start from the top.
		goto restart;
	}

bail:
	return count;
}
