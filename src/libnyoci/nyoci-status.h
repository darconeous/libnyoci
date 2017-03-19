/*!	@file nyoci-status.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
**	@brief Session tracking
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

#ifndef NYOCI_STATUS_HEADER_INCLUDED
#define NYOCI_STATUS_HEADER_INCLUDED 1

#if !defined(NYOCI_INCLUDED_FROM_LIBNYOCI_H) && !defined(BUILDING_LIBNYOCI)
#error "Do not include this header directly, include <libnyoci/libnyoci.h> instead"
#endif

NYOCI_BEGIN_C_DECLS

/*!	@addtogroup nyoci
**	@{
*/

enum {
	NYOCI_STATUS_OK                  = 0,	//!< Success. No error.
	NYOCI_STATUS_FAILURE             = -1,	//!< Unspecified failure.
	NYOCI_STATUS_INVALID_ARGUMENT    = -2,	//!< An argument or parameter was out of spec.
	NYOCI_STATUS_UNSUPPORTED_URI     = -4,	//!< The given URI is unsupported.
	NYOCI_STATUS_ERRNO               = -5,	//!< Unix socket error. (errno)
	NYOCI_STATUS_MALLOC_FAILURE      = -6,	//!< Out of memory.
	NYOCI_STATUS_TRANSACTION_INVALIDATED = -7,
	NYOCI_STATUS_TIMEOUT             = -8,	//!< Operation was taking too long.
	NYOCI_STATUS_NOT_IMPLEMENTED     = -9,	//!< Feature hasn't been implemented.
	NYOCI_STATUS_NOT_FOUND           = -10,
	NYOCI_STATUS_H_ERRNO             = -11,
	NYOCI_STATUS_RESPONSE_NOT_ALLOWED = -12,
	NYOCI_STATUS_BAD_HOSTNAME        = -13,
	NYOCI_STATUS_LOOP_DETECTED       = -14,
	NYOCI_STATUS_BAD_ARGUMENT        = -15,
	NYOCI_STATUS_HOST_LOOKUP_FAILURE = -16,
	NYOCI_STATUS_MESSAGE_TOO_BIG     = -17,
	NYOCI_STATUS_NOT_ALLOWED			= -18,
	NYOCI_STATUS_URI_PARSE_FAILURE	= -19,
	NYOCI_STATUS_WAIT_FOR_DNS        = -20,
	NYOCI_STATUS_BAD_OPTION			= -21,
	NYOCI_STATUS_DUPE				= -22,
	NYOCI_STATUS_RESET				= -23,
	NYOCI_STATUS_ASYNC_RESPONSE		= -24,
	NYOCI_STATUS_UNAUTHORIZED		= -25,
	NYOCI_STATUS_BAD_PACKET			= -26,
	NYOCI_STATUS_MULTICAST_NOT_SUPPORTED		= -27,
	NYOCI_STATUS_WAIT_FOR_SESSION    = -28,
	NYOCI_STATUS_SESSION_ERROR       = -29,
	NYOCI_STATUS_SESSION_CLOSED      = -30,
	NYOCI_STATUS_OUT_OF_SESSIONS     = -31,
	NYOCI_STATUS_UNSUPPORTED_MEDIA_TYPE = -32,
	//! When returned from a resend callback (in a transaction), stop sending packets without invalidate the transaction
	NYOCI_STATUS_STOP_RESENDING		= -33
};

typedef int nyoci_status_t;

NYOCI_API_EXTERN coap_code_t nyoci_convert_status_to_result_code(nyoci_status_t status);

NYOCI_API_EXTERN const char* nyoci_status_to_cstr(nyoci_status_t x);

/*!	@} */

NYOCI_END_C_DECLS

#endif // NYOCI_STATUS_HEADER_INCLUDED