/* src/libnyoci/nyoci-config.h.  Generated from nyoci-config.h.in by configure.  */
/*!	@file nyoci-config.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
**	@brief LibNyoci Build Options
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

/* #undef NYOCI_EMBEDDED */

/* #undef NYOCI_SINGLETON */

/* #undef NYOCI_PLAT_NET_POSIX_FAMILY */

#define NYOCI_PLAT_NET posix

/* #undef NYOCI_PLAT_TLS */

/* #undef NYOCI_AVOID_MALLOC */

/* #undef NYOCI_AVOID_PRINTF */

/* #undef NYOCI_DEFAULT_PORT */

/* #undef NYOCI_CONF_DUPE_BUFFER_SIZE */

/* #undef NYOCI_CONF_ENABLE_VHOSTS */

/* #undef NYOCI_CONF_MAX_ALLOCED_NODES */

/* #undef NYOCI_CONF_MAX_GROUPS */

/* #undef NYOCI_CONF_MAX_OBSERVERS */

/* #undef NYOCI_CONF_MAX_PAIRINGS */

/* #undef NYOCI_CONF_MAX_TIMEOUT */

/* #undef NYOCI_CONF_NODE_ROUTER */

/* #undef NYOCI_CONF_TRANS_ENABLE_BLOCK2 */

/* #undef NYOCI_CONF_TRANS_ENABLE_OBSERVING */

/* #undef NYOCI_CONF_USE_DNS */

/* #undef NYOCI_ADD_NEWLINES_TO_LIST_OUTPUT */

/* #undef NYOCI_ASYNC_RESPONSE_MAX_LENGTH */

/* #undef NYOCI_DEBUG_INBOUND_DROP_PERCENT */

/* #undef NYOCI_DEBUG_OUTBOUND_DROP_PERCENT */

/* #undef NYOCI_MAX_CASCADE_COUNT */

/* #undef NYOCI_MAX_CONTENT_LENGTH */

/* #undef NYOCI_MAX_OBSERVERS */

/* #undef NYOCI_MAX_PACKET_LENGTH */

/* #undef NYOCI_MAX_PATH_LENGTH */

/* #undef NYOCI_MAX_URI_LENGTH */

/* #undef NYOCI_MAX_VHOSTS */

/* #undef NYOCI_TRANSACTION_BURST_COUNT */

/* #undef NYOCI_TRANSACTION_BURST_TIMEOUT_MAX */

/* #undef NYOCI_TRANSACTION_BURST_TIMEOUT_MIN */

/* #undef NYOCI_THREAD_SAFE */

/* #undef NYOCI_NODE_ROUTER_USE_BTREE */

/* #undef NYOCI_OBSERVATION_DEFAULT_MAX_AGE */

/* #undef NYOCI_OBSERVATION_KEEPALIVE_INTERVAL */

/* #undef NYOCI_OBSERVER_CON_EVENT_EXPIRATION */

/* #undef NYOCI_OBSERVER_NON_EVENT_EXPIRATION */

/* #undef NYOCI_TRANSACTIONS_USE_BTREE */

/* #undef NYOCI_TRANSACTION_BURST_COUNT */

/* #undef NYOCI_TRANSACTION_POOL_SIZE */

/* #undef NYOCI_USE_CASCADE_COUNT */

/* #undef NYOCI_VARIABLE_MAX_KEY_LENGTH */

/* #undef NYOCI_VARIABLE_MAX_VALUE_LENGTH */

#define NYOCI_INTERNAL_EXTERN __attribute__((visibility("default"))) extern

#define NYOCI_API_EXTERN __attribute__((visibility("default"))) extern

/* #undef NYOCI_DEPRECATED */
