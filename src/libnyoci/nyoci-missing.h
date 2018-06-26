/*!	@file nyoci_missing.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
**	@brief Replacements for missing system functions
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

#ifndef NYOCI_nyoci_missing_h
#define NYOCI_nyoci_missing_h

#if HAVE_CONFIG_H
#include <config.h>
#endif

#if !defined(NYOCI_BEGIN_C_DECLS) || !defined(NYOCI_END_C_DECLS)
#if defined(__cplusplus)
#define NYOCI_BEGIN_C_DECLS   extern "C" {
#define NYOCI_END_C_DECLS }
#else
#define NYOCI_BEGIN_C_DECLS
#define NYOCI_END_C_DECLS
#endif
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>      // For ssize_t
#include <string.h>

NYOCI_BEGIN_C_DECLS

#if !HAVE_CONFIG_H

#ifndef HAVE_STPNCPY
#define HAVE_STPNCPY ((defined(linux) || (!defined(__APPLE__) && !defined(__AVR__))) && !defined(__SDCC))
#endif

#ifndef HAVE_STRDUP
#define HAVE_STRDUP (!defined(__SDCC))
#endif

#ifndef HAVE_ALLOCA
#define HAVE_ALLOCA (!defined(__SDCC))
#endif

#ifndef HAVE_STRTOL
#define HAVE_STRTOL (!defined(__SDCC))
#endif

#if !NYOCI_AVOID_PRINTF
#ifndef HAVE_VSNPRINTF
#define HAVE_VSNPRINTF (!defined(__SDCC))
#endif

#endif //!HAVE_CONFIG_H

#if defined(HAVE_ALLOCA_H) && !defined(HAVE_ALLOCA)
#define HAVE_ALLOCA HAVE_ALLOCA_H
#endif

#if !NYOCI_AVOID_PRINTF && !HAVE_VSNPRINTF && !defined(vsnprintf)
#warning VSNPRINTF NOT IMPLEMENTED, VSPRINTF COULD OVERFLOW!
#define vsnprintf(d,n,fmt,lst) vsprintf(d,fmt,lst)
#endif
#endif

#if !NYOCI_AVOID_MALLOC
#if !HAVE_STRDUP && !defined(strdup)
#define strdup(...) ___nyoci_strdup(__VA_ARGS__)
char* ___nyoci_strdup(const char* cstr);
#endif

#if !HAVE_STRNDUP && !defined(strndup)
#define strndup(...) ___nyoci_strndup(__VA_ARGS__)
char* ___nyoci_strndup(const char* cstr,size_t maxlen);
#endif
#endif //!NYOCI_AVOID_MALLOC

#if !HAVE_STPNCPY && !defined(stpncpy)
#define stpncpy(...) ___nyoci_stpncpy(__VA_ARGS__)
char* ___nyoci_stpncpy(char* dest, const char* src, size_t len);
#endif

#ifndef MIN
#if defined(__GCC_VERSION__)
#define MIN(a, \
		b) ({ __typeof__(a)_a = (a); __typeof__(b)_b = (b); _a < \
			  _b ? _a : _b; })
#else
#define MIN(a,b)	((a)<(b)?(a):(b))	// NAUGHTY!...but compiles
#endif
#endif

#ifndef MAX
#if defined(__GCC_VERSION__)
#define MAX(a, \
		b) ({ __typeof__(a)_a = (a); __typeof__(b)_b = (b); _a > \
			  _b ? _a : _b; })
#else
#define MAX(a,b)	((a)<(b)?(b):(a))	// NAUGHTY!...but compiles
#endif
#endif

NYOCI_END_C_DECLS

#endif
