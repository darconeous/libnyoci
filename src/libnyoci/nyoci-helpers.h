/*!	@file nyoci-helpers.h
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


#ifndef __NYOCI_HELPERS_HEADER__
#define __NYOCI_HELPERS_HEADER__ 1

#include <string.h>

#if !defined(__SDCC) && defined(SDCC)
#define __SDCC	SDCC
#endif

#if defined(__SDCC)
#include <malloc.h>
#endif

#include <stdlib.h>
#include <stdint.h>

#if !defined(NYOCI_BEGIN_C_DECLS) || !defined(NYOCI_END_C_DECLS)
#if defined(__cplusplus)
#define NYOCI_BEGIN_C_DECLS   extern "C" {
#define NYOCI_END_C_DECLS }
#else
#define NYOCI_BEGIN_C_DECLS
#define NYOCI_END_C_DECLS
#endif
#endif

/////////////////////////////////////////////////////////////////////////////

#if !defined(NYOCI_DEPRECATED) && HAVE_FUNC_ATTRIBUTE_DEPRECATED
#define NYOCI_DEPRECATED __attribute__ ((deprecated))
#endif

#if !defined(NYOCI_PURE_FUNC) && HAVE_FUNC_ATTRIBUTE_PURE
#define NYOCI_PURE_FUNC __attribute__((pure))
#endif

#if !defined(NYOCI_NON_RECURSIVE) && NYOCI_EMBEDDED && NYOCI_SINGLETON
#define NYOCI_NON_RECURSIVE    static
#endif

/////////////////////////////////////////////////////////////////////////////

#ifndef NYOCI_API_EXTERN
#define NYOCI_API_EXTERN       extern
#endif

#ifndef NYOCI_INTERNAL_EXTERN
#define NYOCI_INTERNAL_EXTERN      extern
#endif

#ifndef NYOCI_DEPRECATED
#define NYOCI_DEPRECATED
#endif

#ifndef NYOCI_PURE_FUNC
#define NYOCI_PURE_FUNC
#endif

#ifndef NYOCI_NON_RECURSIVE
#define NYOCI_NON_RECURSIVE
#endif

#endif
