/*!	@file nyoci-timer.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
**	@brief Timer scheduling and management
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

#ifndef __NYOCI_TIMER_H__
#define __NYOCI_TIMER_H__ 1

#include "ll.h"
#include "btree.h"

#if !defined(NYOCI_INCLUDED_FROM_LIBNYOCI_H) && !defined(BUILDING_LIBNYOCI)
#error "Do not include this header directly, include <libnyoci/libnyoci.h> instead"
#endif

#if NYOCI_SINGLETON
// On embedded systems, we know we will always only have
// a single nyoci instance, so we can save a considerable
// amount of stack spaces by simply removing the first argument
// from many functions. In order to make things as maintainable
// as possible, these macros do all of the work for us.
#define nyoci_schedule_timer(self,...)		nyoci_schedule_timer(__VA_ARGS__)
#define nyoci_invalidate_timer(self,...)		nyoci_invalidate_timer(__VA_ARGS__)
#define nyoci_handle_timers(self,...)		nyoci_handle_timers(__VA_ARGS__)
#define nyoci_timer_is_scheduled(self,...)		nyoci_timer_is_scheduled(__VA_ARGS__)
#endif

#ifndef MSEC_PER_SEC
#define MSEC_PER_SEC    (1000)
#endif

#ifndef USEC_PER_MSEC
#define USEC_PER_MSEC   (1000)
#endif

#ifndef USEC_PER_SEC
#define USEC_PER_SEC    (1000000)
#endif

NYOCI_BEGIN_C_DECLS
/*!	@addtogroup nyoci
**	@{
*/

/*!	@defgroup nyoci_timer Timer API
**	@{
**	@brief Timer functions.
**
**	LibNyoci has two ways to represent a point in time:
**
**	 * Relative time (`nyoci_cms_t`), measured in milliseconds from "now". The future
**	   is positive and the past is negative.
**	 * Absolute time (`nyoci_timestamp_t`), measured from some platform-specific
**     reference epoc.
**
**	The relative notation is convenient for specifying timeouts and such,
**	but the individual timers store their firing time in absolute time.
**	You can convert between relative time and absolute time using
**	`nyoci_plat_cms_to_timestamp()` and back again using `nyoci_plat_timestamp_to_cms()`.
**
*/

typedef void (*nyoci_timer_callback_t)(nyoci_t, void*);

typedef struct nyoci_timer_s {
	struct ll_item_s		ll;
	nyoci_timestamp_t		fire_date;
	void*					context;
	nyoci_timer_callback_t	callback;
	nyoci_timer_callback_t	cancel;
} *nyoci_timer_t;

NYOCI_API_EXTERN nyoci_timer_t nyoci_timer_init(
	nyoci_timer_t			self,
	nyoci_timer_callback_t	callback,
	nyoci_timer_callback_t	cancel,
	void*					context
);

NYOCI_API_EXTERN nyoci_status_t nyoci_schedule_timer(
	nyoci_t	self,
	nyoci_timer_t	timer,
	nyoci_cms_t			cms
);

NYOCI_API_EXTERN void nyoci_invalidate_timer(nyoci_t self, nyoci_timer_t timer);
NYOCI_API_EXTERN nyoci_cms_t nyoci_get_timeout(nyoci_t self);
NYOCI_API_EXTERN void nyoci_handle_timers(nyoci_t self);
NYOCI_API_EXTERN bool nyoci_timer_is_scheduled(nyoci_t self, nyoci_timer_t timer);

/*!	@} */
/*!	@} */

NYOCI_END_C_DECLS

#endif //__NYOCI_TIMER_H__
