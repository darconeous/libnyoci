/*!	@file nyoci-logging.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
**	@brief Logging support
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

#ifndef __NYOCI_LOGGING_HEADER__
#define __NYOCI_LOGGING_HEADER__ 1

#include "assert-macros.h"

#if !VERBOSE_DEBUG

	#define CSTR(x)     (x)

	#ifndef DEBUG_PRINTF
	#define DEBUG_PRINTF(...)   do { } while(0)
	#endif
	#define NYOCI_DEBUG_OUT_FILE     stdout

#elif defined(__AVR__)
	#define NYOCI_DEBUG_OUT_FILE     stdout

	#include <stdio.h>
	#include <avr/pgmspace.h>
	#define CSTR(x)     PSTR(x)
	#define DEBUG_PRINTF(...) \
	do { fprintf_P(NYOCI_DEBUG_OUT_FILE, __VA_ARGS__); fputc( \
				'\n', \
				NYOCI_DEBUG_OUT_FILE); } while(0)

#elif defined(ESP_PLATFORM)
	#include <esp_log.h>
	#define DEBUG_PRINTF(FMT, ...)   ESP_LOGI("nyoci", FMT, ##__VA_ARGS__)
	#define NYOCI_DEBUG_OUT_FILE     stderr
	#define CSTR(x)     x

#else
	#define NYOCI_DEBUG_OUT_FILE     stderr

	#include <stdio.h>
	#define CSTR(x)     (x)
	#if ASSERT_MACROS_USES_SYSLOG
		#include <syslog.h>
		#define DEBUG_PRINTF(...) syslog(7, __VA_ARGS__)
	#elif ASSERT_MACROS_USE_VANILLA_PRINTF
		#define DEBUG_PRINTF(...) \
			do { printf(__VA_ARGS__); printf("\n"); } while(0)
	#else
		#define DEBUG_PRINTF(...) \
			do { fprintf(NYOCI_DEBUG_OUT_FILE, __VA_ARGS__); fputc('\n', \
					NYOCI_DEBUG_OUT_FILE); } while(0)
	#endif

#endif

#endif // __NYOCI_LOGGING_HEADER__
