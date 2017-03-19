/*!	@file nyoci-observable.h
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

#ifndef __NYOCI_OBSERVABLE_H__
#define __NYOCI_OBSERVABLE_H__ 1

#if !defined(NYOCI_INCLUDED_FROM_LIBNYOCI_H) && !defined(BUILDING_LIBNYOCI)
#error "Do not include this header directly, include <libnyoci/libnyoci.h> instead"
#endif

NYOCI_BEGIN_C_DECLS

/*!	@addtogroup nyoci
**	@{
*/

/*!	@defgroup nyoci-observable Observable API
**	@{
**	@brief Functions for creating observable resources.
**
**	@sa @ref nyoci-example-4
*/

//! Observable context.
/*!	The observable context is a datastructure that keeps track of
**	who is observing which resources. You may have as many or as few as
**	you like.
**
**	@sa nyoci_observable_update(), nyoci_observable_trigger()
*/
struct nyoci_observable_s {
#if !NYOCI_SINGLETON
	nyoci_t interface;
#endif

	// Consider all members below this line as private!

	int8_t first_observer; //!^ always +1, zero is end of list
	int8_t last_observer;  //!^ always +1, zero is end of list
};

//! Key to trigger all observers using the given observable context.
#define NYOCI_OBSERVABLE_BROADCAST_KEY		(0xFF)

typedef struct nyoci_observable_s *nyoci_observable_t;

//!	Hook for making a resource observable.
/*!	This must be called after you have "begun" to compose the outbound
**	response message but *before* you have started to compose the content.
**	More explicitly:
**
**	 * *After* nyoci_outbound_begin() or nyoci_outbound_begin_response()
**	 * *Before* nyoci_outbound_get_content_ptr(), nyoci_outbound_append_content(),
**	   nyoci_outbound_send(), etc.
**
**	You may choose any value for `key`, as long as it matches what you pass
**	to nyoci_observable_trigger() to trigger updates.
*/
NYOCI_API_EXTERN nyoci_status_t nyoci_observable_update(
	nyoci_observable_t context, //!< [IN] Pointer to observable context
	uint8_t key		//!< [IN] Key for this resource (must be same as used in trigger)
);

#define NYOCI_OBS_TRIGGER_FLAG_NO_INCREMENT    (1<<0)
#define NYOCI_OBS_TRIGGER_FLAG_FORCE_CON       (1<<1)

//!	Triggers an observable resource to send an update to its observers.
/*!
**	You may use NYOCI_OBSERVABLE_BROADCAST_KEY for the key to trigger
**	all resources associated with this observable context to update.
*/
NYOCI_API_EXTERN nyoci_status_t nyoci_observable_trigger(
	nyoci_observable_t context, //!< [IN] Pointer to observable context
	uint8_t key,	//!< [IN] Key for this resource (must be same as used in update)
	uint8_t flags	//!< [IN] Flags
);

//!	Triggers all observable resources to send a CON update to their observers.
/*!
**	This is useful to call occasionally to help weed out dead
**	observers, especially when your observable resources change
**	very infrequently. This is broken out into an explicit function
**	rather than being automatic so that you can schedule this to
**	occur at opportune times, like during scheduled wakeups.
*/
NYOCI_API_EXTERN void nyoci_refresh_observers(nyoci_t interface, uint8_t flags);

//! Returns the number of active observers.
NYOCI_API_EXTERN int nyoci_count_observers(nyoci_t interface);

//!	Gets the number of observers for a given resource and key
/*!
**	You may use NYOCI_OBSERVABLE_BROADCAST_KEY for the key to get the
**	count of all observers associated with this context.
*/
NYOCI_API_EXTERN int nyoci_observable_observer_count(
	nyoci_observable_t context, //!< [IN] Pointer to observable context
	uint8_t key	//!< [IN] Key for this resource (must be same as used in update)
);

//!	Removes observers for a given resource and key
/*!
**	You may use NYOCI_OBSERVABLE_BROADCAST_KEY for the key to clear
**	all observers associated with this context.
*/
NYOCI_API_EXTERN int nyoci_observable_clear(
	nyoci_observable_t context, //!< [IN] Pointer to observable context
	uint8_t key	//!< [IN] Key for this resource (must be same as used in update)
);

/*!	@} */
/*!	@} */

NYOCI_END_C_DECLS

#endif
