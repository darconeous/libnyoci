/*	@file nyoci_timer.c
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

//#define ASSERT_MACROS_USE_VANILLA_PRINTF 1
//#define NYOCI_DEBUG_TIMERS	1
//#define VERBOSE_DEBUG 1
//#define DEBUG 1

#include "assert-macros.h"
#include "libnyoci.h"

#if !NYOCI_DEBUG_TIMERS && !VERBOSE_DEBUG
#undef DEBUG_PRINTF
#define DEBUG_PRINTF(fmt, ...) do { } while(0)
#endif

#include <stdio.h>

#include "libnyoci.h"
#include "nyoci-internal.h"

#include "nyoci-logging.h"
#include "url-helpers.h"
#include <string.h>

#ifndef NYOCI_MAX_TIMEOUT
#define NYOCI_MAX_TIMEOUT    (NYOCI_CONF_MAX_TIMEOUT * MSEC_PER_SEC)
#endif

static ll_compare_result_t
nyoci_timer_compare_func(
	const void* lhs_, const void* rhs_, void* context
) {
	const nyoci_timer_t lhs = (nyoci_timer_t)lhs_;
	const nyoci_timer_t rhs = (nyoci_timer_t)rhs_;
	nyoci_cms_t x = nyoci_plat_timestamp_diff(lhs->fire_date, rhs->fire_date);

	if(x > 0) {
		return 1;
	}

	if(x < 0) {
		return -1;
	}

	return 0;
}

nyoci_timer_t
nyoci_timer_init(
	nyoci_timer_t			self,
	nyoci_timer_callback_t	callback,
	nyoci_timer_callback_t	cancel,
	void*					context
) {
	if(self) {
		memset(self, 0, sizeof(*self));
		self->context = context;
		self->callback = callback;
		self->cancel = cancel;
	}
	return self;
}

bool
nyoci_timer_is_scheduled(
	nyoci_t self, nyoci_timer_t timer
) {
	NYOCI_SINGLETON_SELF_HOOK;
	return timer->ll.next || timer->ll.prev || (self->timers == timer);
}

nyoci_status_t
nyoci_schedule_timer(
	nyoci_t	self,
	nyoci_timer_t	timer,
	nyoci_cms_t			cms
) {
	nyoci_status_t ret = NYOCI_STATUS_FAILURE;
	NYOCI_SINGLETON_SELF_HOOK;

	assert(self!=NULL);
	assert(timer!=NULL);

	// Make sure we aren't already part of the list.
	require(!timer->ll.next, bail);
	require(!timer->ll.prev, bail);
	require(self->timers != timer, bail);

	DEBUG_PRINTF("Timer:%p: Scheduling to fire in %dms ...",timer,cms);
#if NYOCI_DEBUG_TIMERS
	size_t previousTimerCount = ll_count(self->timers);
#endif

	if (cms < 0) {
		cms = 0;
	}

	timer->fire_date = nyoci_plat_cms_to_timestamp(cms);

	ll_sorted_insert(
			(void**)&self->timers,
		timer,
		&nyoci_timer_compare_func,
		NULL
	);

	ret = NYOCI_STATUS_OK;

	DEBUG_PRINTF("Timer:%p(CTX=%p): Scheduled.",timer,timer->context);
	DEBUG_PRINTF("%p: Timers in play = %d",self,(int)ll_count(self->timers));

#if NYOCI_DEBUG_TIMERS
	assert((ll_count(self->timers)) == previousTimerCount+1);
#endif

bail:
	return ret;
}

void
nyoci_invalidate_timer(
	nyoci_t	self,
	nyoci_timer_t	timer
) {
	NYOCI_SINGLETON_SELF_HOOK;
#if NYOCI_DEBUG_TIMERS
	size_t previousTimerCount = ll_count(self->timers);
	// Sanity check. If we don't have at least one timer
	// then we know something is off.
	check(previousTimerCount>=1);
#endif

	DEBUG_PRINTF("Timer:%p: Invalidating...",timer);
	DEBUG_PRINTF("Timer:%p: (CTX=%p)",timer,timer->context);

	ll_remove((void**)&self->timers, (void*)timer);

#if NYOCI_DEBUG_TIMERS
	check((ll_count(self->timers)) == previousTimerCount-1);
#endif
	timer->ll.next = NULL;
	timer->ll.prev = NULL;
	if(timer->cancel)
		(*timer->cancel)(self,timer->context);
	DEBUG_PRINTF("Timer:%p: Invalidated.",timer);
	DEBUG_PRINTF("%p: Timers in play = %d",self,(int)ll_count(self->timers));
}

#if NYOCI_DEBUG_TIMERS || VERBOSE_DEBUG
void
nyoci_dump_all_timers(nyoci_t self) {
	nyoci_timer_t iter;

	if (self->timers) {
		DEBUG_PRINTF("nyoci(%p): Current Timers:",self);

		for (iter = self->timers;iter;iter = (void*)iter->ll.next) {
			DEBUG_PRINTF("\t* [%p] expires-in:%dms context:%p",iter,nyoci_plat_timestamp_to_cms(iter->fire_date),iter->context);
		}
	} else {
		DEBUG_PRINTF("nyoci(%p): No timers active.",self);
	}
}
#endif

nyoci_cms_t
nyoci_get_timeout(nyoci_t self) {
	nyoci_cms_t ret = NYOCI_MAX_TIMEOUT;
	NYOCI_SINGLETON_SELF_HOOK;

	if (self->timers) {
		ret = MIN(ret, nyoci_plat_timestamp_to_cms(self->timers->fire_date));
	}

	ret = MAX(ret, 0);

#if VERBOSE_DEBUG
	if (ret != NYOCI_MAX_TIMEOUT) {
		nyoci_dump_all_timers(self);
		DEBUG_PRINTF("%p: next timeout = %dms", self, ret);
	}
#endif
	return ret;
}

void
nyoci_handle_timers(nyoci_t self) {
	NYOCI_SINGLETON_SELF_HOOK;
	nyoci_set_current_instance(self);
	if (self->timers
		&& (nyoci_plat_timestamp_to_cms(self->timers->fire_date) <= 0)
	) {
		NYOCI_NON_RECURSIVE nyoci_timer_t timer;
		NYOCI_NON_RECURSIVE nyoci_timer_callback_t callback;
		NYOCI_NON_RECURSIVE void* context;

		timer = self->timers;
		callback = timer->callback;
		context = timer->context;

		DEBUG_PRINTF("Timer:%p(CTX=%p): Firing...",timer,timer->context);

		timer->cancel = NULL;
		nyoci_invalidate_timer(self, timer);
		if (callback) {
			callback(self, context);
		}
	}
#if NYOCI_DEBUG_TIMERS
	nyoci_dump_all_timers(self);
#endif
}
