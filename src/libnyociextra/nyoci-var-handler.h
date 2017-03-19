/*!	@file nyoci-var-handler.h
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

#ifndef __NYOCI_variable_handler_H__
#define __NYOCI_variable_handler_H__ 1

#include <libnyoci/libnyoci.h>

NYOCI_BEGIN_C_DECLS

/*!	@addtogroup nyoci-extras
**	@{
*/

/*!	@defgroup nyoci-var-handler Variable Node
**	@{
*/

struct nyoci_var_handler_s;
typedef struct nyoci_var_handler_s *nyoci_var_handler_t;

enum {
	NYOCI_VAR_GET_KEY,
	NYOCI_VAR_CHECK_KEY,
	NYOCI_VAR_SET_VALUE,
	NYOCI_VAR_GET_VALUE,
	NYOCI_VAR_GET_LF_TITLE,
	NYOCI_VAR_GET_MAX_AGE,
	NYOCI_VAR_GET_ETAG,
	NYOCI_VAR_GET_OBSERVABLE,
};

typedef nyoci_status_t (*nyoci_var_handler_func)(
	nyoci_var_handler_t node,
	uint8_t action,
	uint8_t i,
	char* value
);

struct nyoci_var_handler_s {
	nyoci_var_handler_func func;
	struct nyoci_observable_s observable;
};

NYOCI_API_EXTERN nyoci_status_t nyoci_var_handler_request_handler(
	nyoci_var_handler_t		node
);

/*!	@} */
/*!	@} */

NYOCI_END_C_DECLS

#endif //__NYOCI_TIMER_NODE_H__
