/*	@file url-helpers.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
**
**	Originally published 2010-8-31.
**
**	This file was written by Robert Quattlebaum <darco@deepdarc.com>.
**
**	This work is provided as-is. Unless otherwise provided in writing,
**	Robert Quattlebaum makes no representations or warranties of any
**	kind concerning this work, express, implied, statutory or otherwise,
**	including without limitation warranties of title, merchantability,
**	fitness for a particular purpose, non infringement, or the absence
**	of latent or other defects, accuracy, or the present or absence of
**	errors, whether or not discoverable, all to the greatest extent
**	permissible under applicable law.
**
**	To the extent possible under law, Robert Quattlebaum has waived all
**	copyright and related or neighboring rights to this work. This work
**	is published from the United States.
**
**	I, Robert Quattlebaum, dedicate any and all copyright interest in
**	this work to the public domain. I make this dedication for the
**	benefit of the public at large and to the detriment of my heirs and
**	successors. I intend this dedication to be an overt act of
**	relinquishment in perpetuity of all present and future rights to
**	this code under copyright law. In jurisdictions where this is not
**	possible, I hereby release this code under the Creative Commons
**	Zero (CC0) license.
**
**	 * <http://creativecommons.org/publicdomain/zero/1.0/>
*/

#ifndef __URL_HELPERS_H__
#define __URL_HELPERS_H__ 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*!	@defgroup url-helpers URL Helpers
**	@{
*/

#define URL_HELPERS_MAX_URL_COMPONENTS      (15)

#define MAX_URL_SIZE        (256)

/*!	Perfoms a URL encoding of the given string.
**	@returns	Number of bytes in encoded string
*/
NYOCI_INTERNAL_EXTERN size_t url_encode_cstr(
	char *dest,				//!< [OUT] Destination C-string
	const char* src,		//!< [IN] Must be zero-terminated.
	size_t dest_max_size
);

NYOCI_INTERNAL_EXTERN size_t url_encode_str(
	char *dest,
	size_t dest_max_size,
	const char* src,		//!< Length determined by `src_len`.
	size_t src_len
);

NYOCI_INTERNAL_EXTERN size_t url_decode_str(
	char *dest,
	size_t dest_max_size,
	const char* src,		//!< Length determined by `src_len`.
	size_t src_len
);

/*!	Perfoms a URL decoding of the given string.
**	@returns	Number of bytes in decoded string
*/
NYOCI_INTERNAL_EXTERN size_t url_decode_cstr(
	char *dest,
	const char* src,		//!< Must be zero-terminated.
	size_t dest_max_size
);

NYOCI_INTERNAL_EXTERN void url_decode_cstr_inplace(char *str);


NYOCI_INTERNAL_EXTERN size_t quoted_cstr(
	char *dest,
	const char* src,		//!< Must be zero-terminated.
	size_t dest_max_size
);

NYOCI_INTERNAL_EXTERN size_t url_form_next_value(
	char** form_string, //!< [IN/OUT]
	char** key,			//!< [OUT]
	char** value		//!< [OUT]
);

NYOCI_INTERNAL_EXTERN size_t url_path_next_component(
	char** path_string,	//!< [IN/OUT]
	char** component	//!< [OUT]
);

struct url_components_s {
	char* protocol;
	char* username;
	char* password;
	char* host;
	char* port;
	char* path;
	char* query;
};

NYOCI_INTERNAL_EXTERN int url_parse(
	char* url,		//!< [IN] URL to parse (will be modified)
	struct url_components_s* components
);

NYOCI_INTERNAL_EXTERN bool url_is_absolute(const char* url);

NYOCI_INTERNAL_EXTERN bool url_is_root(const char* url);

#if defined(__SDCC)
#define path_is_absolute(path) ((path)[0] == '/')
#else
inline static bool path_is_absolute(const char* path) { return path[0] == '/'; }
#endif

//! Transforms new_url into a shorter, possibly relative, path/url.
NYOCI_INTERNAL_EXTERN void url_shorten_reference(
	const char* current_url,
	char* new_url
);

NYOCI_INTERNAL_EXTERN bool string_contains_colons(const char* str);

NYOCI_INTERNAL_EXTERN bool url_change(
	char* current_url,
	const char* new_url
);

/*!	@} */

#endif // __URL_HELPERS_H__
