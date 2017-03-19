/*!	@file nyoci-session.h
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

#ifndef NYOCI_nyoci_session_h
#define NYOCI_nyoci_session_h

#if !defined(NYOCI_INCLUDED_FROM_LIBNYOCI_H) && !defined(BUILDING_LIBNYOCI)
#error "Do not include this header directly, include <libnyoci/libnyoci.h> instead"
#endif

NYOCI_BEGIN_C_DECLS

/*!	@addtogroup nyoci
**	@{
*/
#define NYOCI_SESSION_TYPE_FLAG_SECURE             (1<<4)
#define NYOCI_SESSION_TYPE_FLAG_MULTICAST          (1<<5)
#define NYOCI_SESSION_TYPE_FLAG_RELIABLE           (1<<6)

typedef enum {
	NYOCI_SESSION_TYPE_NIL     = 0,
	NYOCI_SESSION_TYPE_UDP     = 1 | NYOCI_SESSION_TYPE_FLAG_MULTICAST,
	NYOCI_SESSION_TYPE_TCP     = 2 | NYOCI_SESSION_TYPE_FLAG_RELIABLE,
	NYOCI_SESSION_TYPE_DTLS    = 3 | NYOCI_SESSION_TYPE_FLAG_SECURE,
	NYOCI_SESSION_TYPE_TLS     = 4 | NYOCI_SESSION_TYPE_FLAG_RELIABLE | NYOCI_SESSION_TYPE_FLAG_SECURE,
} nyoci_session_type_t;

#define nyoci_session_type_supports_multicast(x)    (((x)&NYOCI_SESSION_TYPE_FLAG_MULTICAST)==NYOCI_SESSION_TYPE_FLAG_MULTICAST)
#define nyoci_session_type_is_reliable(x)           (((x)&NYOCI_SESSION_TYPE_FLAG_RELIABLE)==NYOCI_SESSION_TYPE_FLAG_RELIABLE)

NYOCI_INTERNAL_EXTERN nyoci_session_type_t nyoci_session_type_from_uri_scheme(const char* uri_scheme);

//!	Returns the default port number for the given session type.
NYOCI_INTERNAL_EXTERN uint16_t nyoci_default_port_from_session_type(nyoci_session_type_t type);

/*!	@} */

NYOCI_END_C_DECLS

#endif
