/*!	@file nyoci-defaults.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
**	@brief LibNyoci Default Build Options
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

#ifndef __NYOCI_DEFAULTS_H__
#define __NYOCI_DEFAULTS_H__

/*****************************************************************************/
// MARK: - LibNyoci Build Parameters

#ifndef VERBOSE_DEBUG
#define VERBOSE_DEBUG 0
#endif

#ifndef NYOCI_EMBEDDED
#define NYOCI_EMBEDDED			(0)
#endif

#ifndef NYOCI_SINGLETON
#define NYOCI_SINGLETON			NYOCI_EMBEDDED
#endif

#ifndef NYOCI_THREAD_SAFE
#define NYOCI_THREAD_SAFE		!NYOCI_EMBEDDED
#endif

#ifndef NYOCI_DEFAULT_PORT
#define NYOCI_DEFAULT_PORT           COAP_DEFAULT_PORT
#endif

#define NYOCI_DEFAULT_PORT_CSTR      #NYOCI_DEFAULT_PORT

#ifndef NYOCI_MAX_PATH_LENGTH
#define NYOCI_MAX_PATH_LENGTH        (127)
#endif

//!	@define NYOCI_MAX_URI_LENGTH
/*!
**	This is calclated as the sum of the following:
**
**	 * `strlen("coap://")`
**	 * `strlen("[0000:0000:0000:0000:0000:0000:0000:0000]:65535")`
**	 * `NYOCI_MAX_PATH_LENGTH`
*/
#ifndef NYOCI_MAX_URI_LENGTH
#if NYOCI_EMBEDDED
#define NYOCI_MAX_URI_LENGTH (7 + 47 + (NYOCI_MAX_PATH_LENGTH) )
#else
#define NYOCI_MAX_URI_LENGTH (1024)
#endif
#endif

//!	@define NYOCI_MAX_PACKET_LENGTH
/*! Maximum supported CoAP packet length.
*/
#if !defined(NYOCI_MAX_PACKET_LENGTH) && !defined(NYOCI_MAX_CONTENT_LENGTH)
#if NYOCI_USE_UIP
#define NYOCI_MAX_PACKET_LENGTH ((UIP_BUFSIZE - UIP_LLH_LEN - UIP_IPUDPH_LEN))
#else
#define NYOCI_MAX_CONTENT_LENGTH     (1024)
#endif
#endif

//!	@define NYOCI_MAX_CONTENT_LENGTH
/*!	The maximum number of *content* bytes allowed in an outgoing packet. */
#if defined(NYOCI_MAX_PACKET_LENGTH) && !defined(NYOCI_MAX_CONTENT_LENGTH)
#define NYOCI_MAX_CONTENT_LENGTH     (NYOCI_MAX_PACKET_LENGTH-8)
#endif

//!	@define NYOCI_MAX_PACKET_LENGTH
/*!	The maximum *total* number of bytes allowed in an outgoing packet. */
#if !defined(NYOCI_MAX_PACKET_LENGTH) && defined(NYOCI_MAX_CONTENT_LENGTH)
#define NYOCI_MAX_PACKET_LENGTH      ((coap_size_t)NYOCI_MAX_CONTENT_LENGTH+8)
#endif

//!	@define NYOCI_AVOID_PRINTF
/*!	If set, use of printf() (or any of its variants) is avoided.
*/
#ifndef NYOCI_AVOID_PRINTF
#define NYOCI_AVOID_PRINTF	NYOCI_EMBEDDED
#endif

//!	@define NYOCI_AVOID_MALLOC
/*!	Prevents LibNyoci from calling malloc.
**
**	If set, static global pools are used instead of malloc/free,
**	where possible. Also applies to functions that use malloc/free,
**	like strdup().
*/
#ifndef NYOCI_AVOID_MALLOC
#define NYOCI_AVOID_MALLOC	NYOCI_EMBEDDED
#endif

//!	@define NYOCI_CONF_USE_DNS
/*!	Determines if LibNyoci can lookup domain names.
*/
#ifndef NYOCI_CONF_USE_DNS
#define NYOCI_CONF_USE_DNS						1
#endif

//!	@define NYOCI_TRANSACTION_POOL_SIZE
/*!	Maximum number of general-purpose active transactions
**
**	NOTE: Only relevant when NYOCI_AVOID_MALLOC is set.
**
**	You can have more than this value if you statically
**	allocate the transactions. Dynamic allocation is
**	disabled if this value is set to zero and NYOCI_AVOID_MALLOC
**	is set.
**
*/
#ifndef NYOCI_TRANSACTION_POOL_SIZE
#define NYOCI_TRANSACTION_POOL_SIZE				2
#endif

//!	@define NYOCI_CONF_MAX_TIMEOUT
/*! The maximum timeout (in seconds) returned form `nyoci_get_timeout()`
*/
#ifndef NYOCI_CONF_MAX_TIMEOUT
#define NYOCI_CONF_MAX_TIMEOUT					3600
#endif

//! @define NYOCI_CONF_DUPE_BUFFER_SIZE
/*! Number of previous packets to keep track of for duplicate detection.
*/
#ifndef NYOCI_CONF_DUPE_BUFFER_SIZE
#if NYOCI_EMBEDDED
#define NYOCI_CONF_DUPE_BUFFER_SIZE				16
#else
#define NYOCI_CONF_DUPE_BUFFER_SIZE				64
#endif
#endif

//! @define NYOCI_CONF_ENABLE_VHOSTS
/*! Determines of virtual host support is included.
*/
#ifndef NYOCI_CONF_ENABLE_VHOSTS
#define NYOCI_CONF_ENABLE_VHOSTS					!NYOCI_EMBEDDED
#endif

//! @define NYOCI_MAX_VHOSTS
/*! The maximum number of supported vhosts.
*/
#ifndef NYOCI_MAX_VHOSTS
#if NYOCI_EMBEDDED
#define NYOCI_MAX_VHOSTS							3
#else
#define NYOCI_MAX_VHOSTS							16
#endif
#endif

#ifndef NYOCI_CONF_TRANS_ENABLE_BLOCK2
#define NYOCI_CONF_TRANS_ENABLE_BLOCK2			!NYOCI_EMBEDDED
#endif

#ifndef NYOCI_CONF_TRANS_ENABLE_OBSERVING
#define NYOCI_CONF_TRANS_ENABLE_OBSERVING		!NYOCI_EMBEDDED
#endif

//! @define NYOCI_TRANSACTIONS_USE_BTREE
/*! Determines if transactions should be stored in a linked list
**	or a binary tree. Binary tree is faster when there are lots
**	of transactions, but linked lists are smaller and faster when
**	there are few or infrequent transactions.
*/
#ifndef NYOCI_TRANSACTIONS_USE_BTREE
#define NYOCI_TRANSACTIONS_USE_BTREE				!NYOCI_EMBEDDED
#endif

//! @define NYOCI_TRANSACTION_BURST_COUNT
/*!	Number of retransmit attempts during a burst. */
#ifndef NYOCI_TRANSACTION_BURST_COUNT
#define NYOCI_TRANSACTION_BURST_COUNT 3
#endif

//! @define NYOCI_TRANSACTION_BURST_TIMEOUT_MAX
/*!	Maximum time (in milliseconds) between burst packet
**	retransmits when using the burst retransmit strategy. */
#ifndef NYOCI_TRANSACTION_BURST_TIMEOUT_MAX
#define NYOCI_TRANSACTION_BURST_TIMEOUT_MAX 50
#endif

//! @define NYOCI_TRANSACTION_BURST_TIMEOUT_MIN
/*!	Minimum time (in milliseconds) between burst packet
**	retransmits when using the burst retransmit strategy. */
#ifndef NYOCI_TRANSACTION_BURST_TIMEOUT_MIN
#define NYOCI_TRANSACTION_BURST_TIMEOUT_MIN 20
#endif

#ifndef NYOCI_ASYNC_RESPONSE_MAX_LENGTH
#if NYOCI_EMBEDDED
#define NYOCI_ASYNC_RESPONSE_MAX_LENGTH		80
#else
#define NYOCI_ASYNC_RESPONSE_MAX_LENGTH		NYOCI_MAX_PACKET_LENGTH
#endif
#endif

/*****************************************************************************/
// MARK: - Debugging

#ifdef NYOCI_CONF_DEBUG_INBOUND_DROP_PERCENT
#define NYOCI_DEBUG_INBOUND_DROP_PERCENT	(NYOCI_CONF_DEBUG_INBOUND_DROP_PERCENT)
#endif

#ifdef NYOCI_CONF_DEBUG_OUTBOUND_DROP_PERCENT
#define NYOCI_DEBUG_OUTBOUND_DROP_PERCENT (NYOCI_CONF_DEBUG_OUTBOUND_DROP_PERCENT)
#endif

/*****************************************************************************/
// MARK: - Observation Options

#ifdef NYOCI_CONF_MAX_OBSERVERS
#define NYOCI_MAX_OBSERVERS			(NYOCI_CONF_MAX_OBSERVERS)
#else
#if NYOCI_EMBEDDED
#define NYOCI_MAX_OBSERVERS			(2)
#else
#define NYOCI_MAX_OBSERVERS			(64)
#endif
#endif

#ifndef NYOCI_OBSERVATION_KEEPALIVE_INTERVAL
#define NYOCI_OBSERVATION_KEEPALIVE_INTERVAL		(45*MSEC_PER_SEC)
#endif

#ifndef NYOCI_OBSERVATION_DEFAULT_MAX_AGE
#define NYOCI_OBSERVATION_DEFAULT_MAX_AGE		(30*MSEC_PER_SEC)
#endif

#ifndef NYOCI_OBSERVER_CON_EVENT_EXPIRATION
#define NYOCI_OBSERVER_CON_EVENT_EXPIRATION		(10*MSEC_PER_SEC)
#endif

#ifndef NYOCI_OBSERVER_NON_EVENT_EXPIRATION
#define NYOCI_OBSERVER_NON_EVENT_EXPIRATION		(1*MSEC_PER_SEC)
#endif

/*****************************************************************************/
// MARK: - Extras

#ifndef NYOCI_CONF_MAX_PAIRINGS
#if NYOCI_EMBEDDED
#define NYOCI_CONF_MAX_PAIRINGS				2
#else
#define NYOCI_CONF_MAX_PAIRINGS				16
#endif
#endif

#ifndef NYOCI_CONF_MAX_GROUPS
#if NYOCI_EMBEDDED
#define NYOCI_CONF_MAX_GROUPS				2
#else
#define NYOCI_CONF_MAX_GROUPS				16
#endif
#endif

#ifndef NYOCI_NODE_ROUTER_USE_BTREE
#define NYOCI_NODE_ROUTER_USE_BTREE				NYOCI_TRANSACTIONS_USE_BTREE
#endif

//!	@define NYOCI_CONF_MAX_ALLOCED_NODES
/*!	Node Router: Maximum number of allocated nodes
**
**	Only relevant when NYOCI_AVOID_MALLOC is set.
*/
#ifndef NYOCI_CONF_MAX_ALLOCED_NODES
#define NYOCI_CONF_MAX_ALLOCED_NODES				0
#endif

//!	@define NYOCI_ADD_NEWLINES_TO_LIST_OUTPUT
/*!	If set, newlines are added to list output when using the node router.
**
**	@sa NYOCI_CONF_NODE_ROUTER
*/
#ifndef NYOCI_ADD_NEWLINES_TO_LIST_OUTPUT
#if DEBUG
#define NYOCI_ADD_NEWLINES_TO_LIST_OUTPUT	(1)
#else
#define NYOCI_ADD_NEWLINES_TO_LIST_OUTPUT	(0)
#endif
#endif

#ifndef NYOCI_VARIABLE_MAX_VALUE_LENGTH
#define NYOCI_VARIABLE_MAX_VALUE_LENGTH		(127)
#endif

#ifndef NYOCI_VARIABLE_MAX_KEY_LENGTH
#define NYOCI_VARIABLE_MAX_KEY_LENGTH		(23)
#endif

#if defined(NYOCI_PLAT_TLS)
#define NYOCI_DTLS							1
#endif

/*****************************************************************************/
// MARK: - Experimental Options

//!	@define NYOCI_USE_CASCADE_COUNT
/*!	If set, add experiental support an event cascade counter.
**	This is used to prevent storms of events if a device is misconfigured.
*/
#ifndef NYOCI_USE_CASCADE_COUNT
#define NYOCI_USE_CASCADE_COUNT      (0)
#endif

//!	@define NYOCI_MAX_CASCADE_COUNT
/*!	The initial value of the cascade count option.
*/
#ifndef NYOCI_MAX_CASCADE_COUNT
#define NYOCI_MAX_CASCADE_COUNT      (128)
#endif

#endif
