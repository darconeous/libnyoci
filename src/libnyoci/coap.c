/*	@file coap.c
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

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include "assert-macros.h"
#include "nyoci-logging.h"
#include "nyoci-helpers.h"
#include "nyoci-internal.h"
#include "nyoci-missing.h"

#if CONTIKI
#include "contiki.h"
#endif

#include "coap.h"
#include <stdlib.h>
#include "ctype.h"

#if NYOCI_USE_UIP
#include "net/ip/uip.h"
#define htons(x)    uip_htons(x)
#define ntohs(x)    uip_ntohs(x)
#endif

uint8_t*
coap_decode_option(const uint8_t* buffer, coap_option_key_t* key, const uint8_t** value, coap_size_t* lenP) {
	coap_size_t len;

again:

	len = (*buffer & 0x0F);

	switch((*buffer >> 4)) {
		default:
			if(key) *key += (*buffer >> 4);
			buffer += 1;
			break;

		case 13:
			buffer += 1;
			if(key)*key += 13+*buffer;
			buffer += 1;
			break;

		case 14:
			buffer += 1;
			if(key)*key += 269+buffer[1]+(buffer[0]<<8);

			buffer += 2;
			break;

		case 15:
			// End of option marker...?
			// TODO: Fail harder if len doesn't equal 15 as well!
			if (key) *key = COAP_OPTION_INVALID;
			if (value) *value = NULL;
			if (lenP) *lenP = 0;
			return NULL;
			break;
	}

	switch(len) {
		default:
			break;

		case 13:
			len = 13 + *buffer;
			buffer += 1;
			break;

		case 14:
			len = 269+buffer[1]+(coap_size_t)(buffer[0]<<8);
			buffer += 2;
			break;

		case 15:
			// End of option marker...?
			// TODO: Fail harder if len doesn't equal 15 as well!
			if(key)*key = COAP_OPTION_INVALID;
			if(value)*value = NULL;
			if(lenP)*lenP = 0;
			return NULL;
			break;
	}

	if(lenP) *lenP = len;
	if(value) *value = buffer;

	return (uint8_t*)buffer + len;
}

uint8_t*
coap_encode_option(
	uint8_t* buffer,
	coap_option_key_t prev_key,
	coap_option_key_t key,
	const uint8_t* value,
	coap_size_t len
) {
	uint8_t value_offset = 1;
	uint16_t option_delta = key - prev_key;

	if(option_delta>=269) {
		option_delta -= 269;
		buffer[0] = (14<<4);
		buffer[1] = (option_delta >> 8);
		buffer[2] = (option_delta & 0xFF);
		value_offset += 2;
	} else if(option_delta>=13) {
		buffer[0] = (13<<4);
		buffer[1] = (uint8_t)option_delta - 13;
		value_offset += 1;
	} else {
		*buffer = (uint8_t)(option_delta<<4);
	}

	check(len <= (COAP_MAX_OPTION_VALUE_SIZE));

	if(len > COAP_MAX_OPTION_VALUE_SIZE)
		len = COAP_MAX_OPTION_VALUE_SIZE;

	if(len>=269) {
		buffer[0] |= 14;
		buffer[value_offset] = ((len-269)>>8);
		buffer[value_offset+1] = ((len-269)&0xFF);
		value_offset+=2;
	} else if(len>=13) {
		buffer[0] |= 13;
		buffer[value_offset] = (uint8_t)len - 13;
		value_offset += 1;
	} else {
		buffer[0] |= (len & 15);
	}

	buffer += value_offset;

	memmove(buffer, value, len);

	buffer += len;

	return buffer;
}

coap_size_t coap_insert_option(
	uint8_t* start_of_options,
	uint8_t* end_of_options,
	coap_option_key_t key,
	const uint8_t* value,
	coap_size_t len
) {
	coap_size_t size_diff = 0;
	uint8_t* iter = start_of_options;
	uint8_t* insertion_point = start_of_options;
	coap_option_key_t prev_key = 0;
	coap_option_key_t iter_key = 0;

	// Find the insertion point.
	if (start_of_options == end_of_options) {
		iter = NULL;

	} else {
		do {
			iter = coap_decode_option(iter, &iter_key, NULL, NULL);

			if (iter_key <= key) {
				insertion_point = iter;
				prev_key = iter_key;
			}

			if (iter_key > key) {
				break;
			}
		} while(iter && (iter < end_of_options));
	}

	if ( iter != NULL
	  && ((iter_key > key) || (iter < end_of_options))
	) {
		const uint8_t* next_value=NULL;
		coap_size_t next_len=0;

		size_diff += len + 1;

		if (len >= 13) {
			size_diff++;
		}

		if (len >= 269) {
			size_diff++;
		}

		if ((key - prev_key) >= 13) {
			size_diff++;
		}

		if ((key - prev_key) >= 269) {
			size_diff++;
		}

		if ((insertion_point[0] & 0xF0) == (13<<4)) {
			size_diff--;
		} else if ((insertion_point[0] & 0xF0) == (14<<4)) {
			size_diff -= 2;
		}

		if ((iter_key - key) >= 13) {
			size_diff++;
		}

		if ((iter_key - key) >= 269) {
			size_diff++;
		}

		// Move higher options
		if (size_diff) {
			memmove(
				insertion_point + size_diff,
				insertion_point,
				end_of_options - insertion_point
			);
		}

		coap_decode_option(
			insertion_point + size_diff,
			NULL,
			&next_value,
			&next_len
		);

		// encode new option
		iter = coap_encode_option(insertion_point, prev_key, key, value, len);

		// Update fisrt option after
		coap_encode_option(iter, key, iter_key, next_value, next_len);

	} else {
		// Trivial case: Just append.
		size_diff = (coap_size_t)(
			coap_encode_option(
				end_of_options,
				prev_key,
				key,
				value,
				len
			) - end_of_options
		);
	}

bail:
	return size_diff;
}

uint16_t coap_to_http_code(uint8_t x) { return (uint16_t)COAP_TO_HTTP_CODE(x); }

uint8_t http_to_coap_code(uint16_t x) { return (uint8_t)HTTP_TO_COAP_CODE(x); }

bool
coap_option_strequal(const char* optionptr,const char* cstr) {
	// TODO: This looks easily optimizable.
	const char* value;
	coap_size_t value_len;
	coap_size_t i;
	if(!coap_decode_option((const uint8_t*)optionptr, NULL, (const uint8_t**)&value, &value_len))
		return false;

	for(i=0;i<value_len;i++) {
		if(!cstr[i] || (value[i]!=cstr[i]))
			return false;
	}
	return cstr[i]==0;
}

void
coap_decode_block(struct coap_block_info_s* block_info, uint32_t block)
{
	block_info->block_size = (uint16_t)(1<<((block&0x7)+4));
	block_info->block_offset = (block>>4) * block_info->block_size;
	block_info->block_m = !!(block&(1<<3));
}

/*
uint32_t
coap_encode_block(const struct coap_block_info_s* block_info)
{
	uint32_t ret = 0;
	if (block_info->block_m) {
		ret |= (1<<3);
	}
	(block_info->block_size-4)
	block_info->block_size = (uint16_t)(1<<((block&0x7)+4));
	block_info->block_offset = (block>>4) * block_info->block_size;
	block_info->block_m = !!(block&(1<<3));
}
*/

bool
coap_verify_packet(const char* packet,coap_size_t packet_size) {
	const struct coap_header_s* const header = (const void*)packet;
	coap_option_key_t key = 0;
	const uint8_t* option_ptr = header->token + header->token_len;

	if (packet_size < 4) {
		// Packet too small
		DEBUG_PRINTF("PACKET CORRUPTED: Too Small");
		return false;
	}

	if (header->version != COAP_VERSION) {
		// Bad version.
		DEBUG_PRINTF("PACKET CORRUPTED: Bad Version (%d, should be %d)", header->version, COAP_VERSION);
		return false;
	}

	if (packet_size > COAP_MAX_MESSAGE_SIZE) {
		// Packet too large
		DEBUG_PRINTF("PACKET CORRUPTED: Too Large: %d (%d max)", packet_size, COAP_MAX_MESSAGE_SIZE);
		return false;
	}

	if (header->token_len > 8) {
		// Token too large
		DEBUG_PRINTF("PACKET CORRUPTED: Bad Token");
		return false;
	}

	if (header->code == COAP_CODE_EMPTY && packet_size != 4) {
		DEBUG_PRINTF("PACKET CORRUPTED: Extra Data With Empty Packet (packet_size = %u)",packet_size);
		return false;
	}

	for(;option_ptr && (unsigned)(option_ptr-(uint8_t*)header)<packet_size && option_ptr[0]!=0xFF;) {
		option_ptr = coap_decode_option(option_ptr, &key, NULL, NULL);
		if(!option_ptr) {
			DEBUG_PRINTF("PACKET CORRUPTED: Premature end of options");
			return false;
		}
		if((unsigned)(option_ptr-(uint8_t*)header)>packet_size) {
			DEBUG_PRINTF("PACKET CORRUPTED: Premature end of options");
			return false;
		}
	}

	if((unsigned)(option_ptr-(uint8_t*)header)>packet_size) {
		// Option too large
		DEBUG_PRINTF("PACKET CORRUPTED: Options overflow packet size");
		return false;
	}

	if((unsigned)(option_ptr-(uint8_t*)header)<packet_size) {
		if(option_ptr && option_ptr[0]==0xFF) {
		} else {
			DEBUG_PRINTF("PACKET CORRUPTED: Missing content marker");
			return false;
		}
	}

	return true;
}

uint32_t
coap_decode_uint32(const uint8_t* value,uint8_t value_len) {
	uint32_t ret = 0;
	for(; value_len; value_len--) {
		ret <<= 8;
		ret += *value++;
	}
	return ret;
}


const char*
coap_content_type_to_cstr(coap_content_type_t content_type) {
	const char* content_type_string = NULL;

	switch(content_type) {
	case COAP_CONTENT_TYPE_UNKNOWN: content_type_string = "unknown"; break;

	case COAP_CONTENT_TYPE_TEXT_PLAIN: content_type_string = "text/plain;charset=utf-8";
		break;



	case COAP_CONTENT_TYPE_APPLICATION_LINK_FORMAT: content_type_string =
			"application/link-format"; break;
	case COAP_CONTENT_TYPE_APPLICATION_XML: content_type_string =
			"application/xml"; break;
	case COAP_CONTENT_TYPE_APPLICATION_OCTET_STREAM: content_type_string =
			"application/octet-stream"; break;
	case COAP_CONTENT_TYPE_APPLICATION_EXI: content_type_string =
			"application/exi"; break;
	case COAP_CONTENT_TYPE_APPLICATION_JSON: content_type_string =
			"application/json"; break;

	case NYOCI_CONTENT_TYPE_APPLICATION_FORM_URLENCODED:
		content_type_string = "application/x-www-form-urlencoded"; break;


#if 0
	case COAP_CONTENT_TYPE_TEXT_XML: content_type_string = "text/xml";
		break;
	case COAP_CONTENT_TYPE_TEXT_CSV: content_type_string = "text/csv";
		break;
	case COAP_CONTENT_TYPE_TEXT_HTML: content_type_string = "text/html";
		break;

	case COAP_CONTENT_TYPE_IMAGE_GIF: content_type_string = "image/gif";
		break;
	case COAP_CONTENT_TYPE_IMAGE_JPEG: content_type_string = "image/jpeg";
		break;
	case COAP_CONTENT_TYPE_IMAGE_PNG: content_type_string = "image/png";
		break;
	case COAP_CONTENT_TYPE_IMAGE_TIFF: content_type_string = "image/tiff";
		break;

	case COAP_CONTENT_TYPE_AUDIO_RAW: content_type_string = "audio/raw";
		break;
	case COAP_CONTENT_TYPE_VIDEO_RAW: content_type_string = "video/raw";
		break;
#endif

	default: break;
	}
	if(!content_type_string) {
#if NYOCI_AVOID_PRINTF
		content_type_string = "unknown";
#else
		// TODO: Make thread safe!
		static char ret[40];
		if(content_type < 20)
			snprintf(ret,
				sizeof(ret),
				"text/x-coap-%u;charset=utf-8",
					(unsigned int)content_type);
		else if(content_type < 40)
			snprintf(ret,
				sizeof(ret),
				"image/x-coap-%u",
					(unsigned int)content_type);
		else if(content_type < 60)
			snprintf(ret, sizeof(ret), "application/x-coap-%u",
					(unsigned int)content_type);
		else if(content_type < 201)
			snprintf(ret, sizeof(ret), "application/x-coap-%u",
					(unsigned int)content_type);
		else
			// Experimental
			snprintf(ret, sizeof(ret), "application/x-coap-%u",
					(unsigned int)content_type);
		content_type_string = ret;
#endif
	}
	return content_type_string;
}

const char*
coap_option_key_to_cstr(
	coap_option_key_t key, bool for_response
) {
	const char* ret = NULL;

	if(!ret) switch(key) {
		case COAP_OPTION_CONTENT_TYPE: ret = "Content-type"; break;
		case COAP_OPTION_MAX_AGE: ret = "Max-age"; break;
		case COAP_OPTION_ETAG: ret = "Etag"; break;
		case COAP_OPTION_IF_MATCH: ret = "If-Match"; break;
		case COAP_OPTION_IF_NONE_MATCH: ret = "If-None-Match"; break;
		case COAP_OPTION_PROXY_URI: ret = "Proxy-uri"; break;
		case COAP_OPTION_URI_HOST: ret = "URI-host"; break;
		case COAP_OPTION_URI_PORT: ret = "URI-port"; break;
		case COAP_OPTION_URI_PATH: ret = "URI-path"; break;
		case COAP_OPTION_URI_QUERY: ret = "URI-query"; break;
		case COAP_OPTION_LOCATION_PATH: ret = "Location-path"; break;
		case COAP_OPTION_LOCATION_QUERY: ret = "Location-query"; break;

		case COAP_OPTION_ACCEPT: ret = "Accept"; break;
		case COAP_OPTION_OBSERVE: ret = "Observe"; break;

		case COAP_OPTION_BLOCK1: ret = "Block1"; break;
		case COAP_OPTION_BLOCK2: ret = "Block2"; break;

		default:
#if NYOCI_AVOID_PRINTF
			ret = "unknown-option";
#else
		{
			// NOTE: Not reentrant or thread safe.
			static char x[48];

			sprintf(x, "X-CoAP-%s%s%s-%u",
				COAP_OPTION_IS_CRITICAL(key)?"critical":"elective",
				COAP_OPTION_IS_UNSAFE(key)?"-unsafe":"",
				COAP_OPTION_IS_NOCACHEKEY(key)?"-nocachekey":"",
				key
			);

			ret = x;
		}
#endif
		break;

#if !defined(__SDCC)
/* -- EXPERIMENTAL AFTER THIS POINT -- */

		case COAP_OPTION_CASCADE_COUNT: ret = "Cascade-count"; break;
		case COAP_OPTION_AUTHENTICATE: ret = for_response?"X-Authenticate":"X-Authorization"; break;
#endif

	}
	return ret;
}

bool
coap_option_value_is_string(coap_option_key_t key) {
	switch(key) {
		case COAP_OPTION_PROXY_URI:
		case COAP_OPTION_ETAG:
		case COAP_OPTION_URI_HOST:
		case COAP_OPTION_URI_QUERY:
		case COAP_OPTION_LOCATION_PATH:
		case COAP_OPTION_LOCATION_QUERY:
		case COAP_OPTION_URI_PATH:
			return true;
			break;
		default:
			break;
	}
	return false;
}

#if !defined(__SDCC)
coap_content_type_t
coap_content_type_from_cstr(const char* x) {
	if(!x)
		return COAP_CONTENT_TYPE_UNKNOWN;

	if(strhasprefix_const(x, "application/x-coap-"))
		x += sizeof("application/x-coap-") - 1;
	else if(strhasprefix_const(x, "text/x-coap-"))
		x += sizeof("text/x-coap-") - 1;
	else if(strhasprefix_const(x, "image/x-coap-"))
		x += sizeof("image/x-coap-") - 1;

	if(isdigit(x[0]))
		return (coap_content_type_t)atoi(x);

	// Standard-defined.
	if(strhasprefix_const(x, "text/plain"))
		return COAP_CONTENT_TYPE_TEXT_PLAIN;
	if(strhasprefix_const(x, "application/xml"))
		return COAP_CONTENT_TYPE_TEXT_PLAIN;
	if(strhasprefix_const(x, "application/exi"))
		return COAP_CONTENT_TYPE_APPLICATION_EXI;
	if(strhasprefix_const(x, "application/link-format"))
		return COAP_CONTENT_TYPE_APPLICATION_LINK_FORMAT;
	if(strhasprefix_const(x, "application/octet-stream"))
		return COAP_CONTENT_TYPE_APPLICATION_OCTET_STREAM;
	if(strhasprefix_const(x, "application/json"))
		return COAP_CONTENT_TYPE_APPLICATION_JSON;

	// Non-standard.
	if(strhasprefix_const(x, "text/xml"))
		return COAP_CONTENT_TYPE_APPLICATION_XML;
	if(strhasprefix_const(x, "text/html"))
		return COAP_CONTENT_TYPE_TEXT_HTML;
	if(strhasprefix_const(x, "application/x-www-form-urlencoded"))
		return NYOCI_CONTENT_TYPE_APPLICATION_FORM_URLENCODED;

	// Fallbacks.
	if(strhasprefix_const(x, "text/"))
		return COAP_CONTENT_TYPE_TEXT_PLAIN;

	return COAP_CONTENT_TYPE_UNKNOWN;
}


coap_option_key_t
coap_option_key_from_cstr(const char* key) {
	if(strcasecmp(key, "Content-type") == 0)
		return COAP_OPTION_CONTENT_TYPE;
	else if(strcasecmp(key, "Max-age") == 0)
		return COAP_OPTION_MAX_AGE;
	else if(strcasecmp(key, "Etag") == 0)
		return COAP_OPTION_ETAG;
	else if(strcasecmp(key, "URI-host") == 0)
		return COAP_OPTION_URI_HOST;
	else if(strcasecmp(key, "Proxy-uri") == 0)
		return COAP_OPTION_PROXY_URI;
	else if(strcasecmp(key, "URI-port") == 0)
		return COAP_OPTION_URI_PORT;
	else if(strcasecmp(key, "Location-path") == 0)
		return COAP_OPTION_LOCATION_PATH;
	else if(strcasecmp(key, "Location-query") == 0)
		return COAP_OPTION_LOCATION_QUERY;
	else if(strcasecmp(key, "URI-path") == 0)
		return COAP_OPTION_URI_PATH;
	else if(strcasecmp(key, "Accept") == 0)
		return COAP_OPTION_ACCEPT;
	else if(strcasecmp(key, "Block1") == 0)
		return COAP_OPTION_BLOCK1;
	else if(strcasecmp(key, "Block2") == 0)
		return COAP_OPTION_BLOCK2;

	return COAP_OPTION_INVALID;
}

#endif

const char*
http_code_to_cstr(int x) {
	switch(x) {
	case COAP_CODE_EMPTY: return "EMPTY"; break;
	case COAP_METHOD_GET: return "GET"; break;
	case COAP_METHOD_POST: return "POST"; break;
	case COAP_METHOD_PUT: return "PUT"; break;
	case COAP_METHOD_DELETE: return "DELETE"; break;
#ifndef __SDCC
	case 231:
	case HTTP_RESULT_CODE_CONTINUE: return "CONTINUE"; break;
	case HTTP_RESULT_CODE_OK: return "OK"; break;
	case HTTP_RESULT_CODE_CONTENT: return "CONTENT"; break;
	case HTTP_RESULT_CODE_VALID: return "VALID"; break;
	case HTTP_RESULT_CODE_CREATED: return "CREATED"; break;
	case HTTP_RESULT_CODE_CHANGED: return "CHANGED"; break;
	case HTTP_RESULT_CODE_DELETED: return "DELETED"; break;
	case HTTP_RESULT_CODE_PARTIAL_CONTENT: return "PARTIAL_CONTENT"; break;
	case HTTP_RESULT_CODE_BAD_OPTION: return "BAD_OPTION"; break;
	case HTTP_RESULT_CODE_NOT_ACCEPTABLE: return "NOT_ACCEPTABLE"; break;
	case HTTP_RESULT_CODE_NOT_MODIFIED: return "NOT_MODIFIED"; break;
	case HTTP_RESULT_CODE_SEE_OTHER: return "SEE_OTHER"; break;
	case HTTP_RESULT_CODE_TEMPORARY_REDIRECT: return "TEMPORARY_REDIRECT";
		break;

	case HTTP_RESULT_CODE_REQUEST_TIMEOUT: return "REQUEST_TIMEOUT"; break;
	case HTTP_RESULT_CODE_PRECONDITION_FAILED: return "PRECONDITION_FAILED"; break;

	case HTTP_RESULT_CODE_BAD_REQUEST: return "BAD_REQUEST"; break;
	case HTTP_RESULT_CODE_UNAUTHORIZED: return "UNAUTHORIZED"; break;
	case HTTP_RESULT_CODE_FORBIDDEN: return "FORBIDDEN"; break;
	case HTTP_RESULT_CODE_NOT_FOUND: return "NOT_FOUND"; break;
	case HTTP_RESULT_CODE_METHOD_NOT_ALLOWED: return "METHOD_NOT_ALLOWED";
		break;
	case HTTP_RESULT_CODE_CONFLICT: return "CONFLICT"; break;
	case HTTP_RESULT_CODE_GONE: return "GONE"; break;
	case HTTP_RESULT_CODE_UNSUPPORTED_MEDIA_TYPE: return
			"UNSUPPORTED_MEDIA_TYPE"; break;

	case HTTP_RESULT_CODE_INTERNAL_SERVER_ERROR: return
			"INTERNAL_SERVER_ERROR"; break;
	case HTTP_RESULT_CODE_NOT_IMPLEMENTED: return "NOT_IMPLEMENTED"; break;
	case HTTP_RESULT_CODE_BAD_GATEWAY: return "BAD_GATEWAY"; break;
	case HTTP_RESULT_CODE_SERVICE_UNAVAILABLE: return "UNAVAILABLE"; break;
	case HTTP_RESULT_CODE_GATEWAY_TIMEOUT: return "TIMEOUT"; break;
	case HTTP_RESULT_CODE_PROXYING_NOT_SUPPORTED: return
			"PROXYING_NOT_SUPPORTED"; break;
#endif
	default:  break;
	}
	return "UNKNOWN";
}

const char* coap_code_to_cstr(int x) { return http_code_to_cstr(coap_to_http_code((uint8_t)x)); }

#ifndef __SDCC
#if NYOCI_EMBEDDED && !__AVR__
#define fprintf(x,...)	printf(__VA_ARGS__)
#define fputs(x,s)	printf("%s",x)
#define fputc(x,s)	printf("%c",x)
#define fwrite(value,value_len,blah,stream)		printf("<REDACTED>")

#endif

void
coap_dump_header(
	FILE*			outstream,
	const char*		prefix,
	const struct coap_header_s* header,
	coap_size_t packet_size
) {
	coap_option_key_t key = 0;
	const uint8_t* value;
	coap_size_t value_len;
	const uint8_t* option_ptr = header->token + header->token_len;
	const char* tt_str = NULL;

	if(!prefix)
		prefix = "";

	if(packet_size<4) {
		fputs(prefix, outstream);
		fprintf(outstream,
			"PACKET CORRUPTED: Packet Too Small: %d\n",
			header->token_len
		);
		return;
	}

#if 0
	// As long as coap_size_t is a uint16_t, then this
	// check is unnecessary.
	// TODO: Add compile-time asssert!
	if (packet_size>65535) {
		fputs(prefix, outstream);
		fprintf(outstream,
			"PACKET CORRUPTED: Packet Too Big: %d\n",
			header->token_len
		);
		return;
	}
#endif

	if (header->version != COAP_VERSION) {
		fputs(prefix, outstream);
		fprintf(outstream,
			"PACKET CORRUPTED: Bad Version (%d)\n",
			header->version
		);
		return;
	}

	if (header->token_len > 8) {
		fputs(prefix, outstream);
		fprintf(outstream,
			"PACKET CORRUPTED: Invalid Token Length (%d)\n",
			header->token_len
		);
		return;
	}

	switch (header->tt) {
		case COAP_TRANS_TYPE_CONFIRMABLE: tt_str = "CON(0)"; break;
		case COAP_TRANS_TYPE_NONCONFIRMABLE: tt_str = "NON(1)"; break;
		case COAP_TRANS_TYPE_ACK: tt_str = "ACK(2)"; break;
		case COAP_TRANS_TYPE_RESET: tt_str = "RES(3)"; break;
	}

	if (header->code >= COAP_RESULT_100) {
		fputs(prefix, outstream);
		fprintf(outstream,
			"CoAP/1.0 %d.%02d %s tt=%s msgid=0x%04X\n",
			header->code>>5,header->code&31,
			coap_code_to_cstr(header->code),
			tt_str,ntohs(header->msg_id)
		);
	} else {
		fputs(prefix, outstream);
		fprintf(outstream, "%s(%d) ", (header->tt==COAP_TRANS_TYPE_RESET)?"RESET":coap_code_to_cstr(header->code),header->code);

		if(header->code) {
			// TODO: output path and query!
			fputs("? ", outstream);
		}

		fprintf(outstream, "CoAP/1.0 tt=%s msgid=0x%04X\n",
			tt_str,ntohs(header->msg_id)
		);
	}

	if (header->token_len) {
		coap_size_t i;
		fputs(prefix, outstream);
		fprintf(outstream, "Token: ");
		for(i = 0; i < header->token_len; i++) {
			fprintf(outstream, "%02X ", (uint8_t)header->token[i]);
		}
		fprintf(outstream, "\n");
	}

	for (;option_ptr && (unsigned)(option_ptr-(uint8_t*)header)<packet_size && option_ptr[0]!=0xFF;) {
		option_ptr = coap_decode_option(option_ptr, &key, &value, &value_len);
		if (!option_ptr) {
			fputs(prefix, outstream);
			fprintf(outstream,"PACKET CORRUPTED: Bad Options\n");
			return;
		}
		if ((unsigned)(option_ptr-(uint8_t*)header)>packet_size) {
			fputs(prefix, outstream);
			fprintf(outstream,"PACKET CORRUPTED: Option value size too big\n");
			return;
		}
		fputs(prefix, outstream);
		fprintf(outstream, "%s: ",
			coap_option_key_to_cstr(key, header->code >= COAP_RESULT_100));

		switch (key) {
		case COAP_OPTION_CASCADE_COUNT:
		case COAP_OPTION_MAX_AGE:
		case COAP_OPTION_URI_PORT:
		case COAP_OPTION_OBSERVE:
		{
			unsigned long v = 0;
			uint8_t i;
			for(i = 0; i < value_len; i++)
				v = (v << 8) + value[i];
			fprintf(outstream, "%lu", v);
		}
		break;
		case COAP_OPTION_CONTENT_TYPE:
		case COAP_OPTION_ACCEPT:
		{
			unsigned long v = 0;
			uint8_t i;
			for(i = 0; i < value_len; i++)
				v = (v << 8) + value[i];
			fprintf(outstream, "%s",coap_content_type_to_cstr((coap_content_type_t)v));
		}
		break;
		case COAP_OPTION_BLOCK1:
		case COAP_OPTION_BLOCK2:
		{
			struct coap_block_info_s block_info;
			uint32_t block = 0;
			uint8_t i;

			for(i = 0; i < value_len; i++)
				block = (block << 8) + value[i];

			coap_decode_block(&block_info, block);

			fprintf(outstream,
				"%ld/%ld/%ld",
				(long)block_info.block_offset,
				(long)block_info.block_m,
				(long)block_info.block_size
			);
		}
		break;

		case COAP_OPTION_URI_PATH:
		case COAP_OPTION_URI_HOST:
		case COAP_OPTION_URI_QUERY:
		case COAP_OPTION_PROXY_URI:
		case COAP_OPTION_LOCATION_PATH:
		case COAP_OPTION_LOCATION_QUERY:
			fprintf(outstream, "\"");
			if(value_len > COAP_MAX_OPTION_VALUE_SIZE)
				fprintf(outstream, "%s",value);
			else
				fwrite(value, value_len, 1, outstream);
			fprintf(outstream, "\"");
			break;

		default:
		{
			coap_size_t i;
			if(value_len > COAP_MAX_OPTION_VALUE_SIZE) {
				fprintf(outstream, "***VALUE LENGTH OVERFLOW***");
			} else
			for(i = 0; i < value_len; i++) {
				fprintf(outstream, "%02X ", (uint8_t)value[i]);
			}
		}
		break;
		}
		fputc('\n', outstream);
	}
	if((unsigned)(option_ptr-(uint8_t*)header)>packet_size) {
		fputs(prefix, outstream);
		fprintf(outstream,"PACKET CORRUPTED: Bad Options\n");
		return;
	}
	if((unsigned)(option_ptr-(uint8_t*)header)<packet_size) {
		if(option_ptr && option_ptr[0]==0xFF) {

			fputs(prefix, outstream);
			fprintf(outstream, "Payload-Size: %zd\n",packet_size-(option_ptr-(uint8_t*)header)-1);
		} else {
			fputs(prefix, outstream);
			fprintf(outstream,"PACKET CORRUPTED: %zd extra bytes\n",packet_size-(option_ptr-(uint8_t*)header));
		}
	}

	fputs(prefix, outstream);
	fputc('\n', outstream);
}
#endif
