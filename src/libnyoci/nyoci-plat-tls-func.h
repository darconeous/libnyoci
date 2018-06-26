/*	@file nyoci-plat-ssl.h
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

#ifndef NYOCI_nyoci_plat_tls_func_h
#define NYOCI_nyoci_plat_tls_func_h

#if !defined(NYOCI_INCLUDED_FROM_LIBNYOCI_H) && !defined(BUILDING_LIBNYOCI)
#error "Do not include this header directly, include <libnyoci/libnyoci.h> instead"
#endif

#define NYOCI_PLAT_TLS_DEFAULT_CONTEXT		NULL

#if NYOCI_SINGLETON
#define nyoci_plat_tls_get_context(self)		nyoci_plat_tls_get_context()
#define nyoci_plat_tls_set_context(self,...)		nyoci_plat_tls_set_context(__VA_ARGS__)
#define nyoci_plat_tls_inbound_packet_process(self,...)		nyoci_plat_tls_inbound_packet_process(__VA_ARGS__)
#define nyoci_plat_tls_outbound_packet_process(self,...)		nyoci_plat_tls_outbound_packet_process(__VA_ARGS__)
#define nyoci_plat_tls_set_client_psk_callback(self,...)        nyoci_plat_tls_set_client_psk_callback(__VA_ARGS__)
#define nyoci_plat_tls_set_server_psk_callback(self,...)        nyoci_plat_tls_set_server_psk_callback(__VA_ARGS__)
#define nyoci_plat_tls_set_psk_hint(self,...)                   nyoci_plat_tls_set_psk_hint(__VA_ARGS__)
#endif

NYOCI_API_EXTERN nyoci_status_t nyoci_plat_tls_init(void);

//! Sets the security context to be associated with this LibNyoci instance.
/*!	The type of object that this pointer referrs to depends on
**	the underlying TLS implementation. For OpenSSL, it is
**	an pointer to an `SSL_CTX` object.
**
**	Passing `NYOCI_PLAT_TLS_DEFAULT_CONTEXT` as the value for `context`
**	will cause a context to be created with reasonable default
**	security settings.
*/
NYOCI_API_EXTERN nyoci_status_t nyoci_plat_tls_set_context(
	nyoci_t self, nyoci_plat_tls_context_t context
);

NYOCI_API_EXTERN nyoci_plat_tls_context_t nyoci_plat_tls_get_context(nyoci_t self);

//! Returns a pointer to the current security session object.
/*!	The type of object that this pointer referrs to depends on
**	the underlying TLS implementation. For OpenSSL, it is
**	an pointer to an `SSL` object.
**
**	This function can only be meaningfuly called from a callback.
*/
NYOCI_API_EXTERN nyoci_plat_tls_session_t nyoci_plat_tls_get_current_session(void);

//!	Sets the intended target hostname for the current security session.
/*!	If the remote host fails to validate against this hostname,
**	then the session will eventually fail with NYOCI_STATUS_SESSION_ERROR.
**
**	This function can only be meaningfuly called from a callback.
*/
NYOCI_API_EXTERN nyoci_status_t nyoci_plat_tls_set_remote_hostname(const char* hostname);

typedef unsigned int (*nyoci_plat_tls_client_psk_callback_func)(
	void* context,
	const char *hint,
	char *identity, unsigned int max_identity_len,
	unsigned char *psk, unsigned int max_psk_len
);

typedef unsigned int (*nyoci_plat_tls_server_psk_callback_func)(
	void* context,
	const char *identity,
	unsigned char *psk, unsigned int max_psk_len
);

NYOCI_API_EXTERN nyoci_status_t nyoci_plat_tls_set_client_psk_callback(nyoci_t self, nyoci_plat_tls_client_psk_callback_func cb, void* context);

NYOCI_API_EXTERN nyoci_status_t nyoci_plat_tls_set_server_psk_callback(nyoci_t self, nyoci_plat_tls_server_psk_callback_func cb, void* context);

NYOCI_API_EXTERN const char* nyoci_plat_tls_get_psk_identity(void);

NYOCI_API_EXTERN nyoci_status_t nyoci_plat_tls_set_psk_hint(nyoci_t self, const char* hint);

//! Called by the platform to dispatch inbound DTLS packets.
NYOCI_API_EXTERN nyoci_status_t nyoci_plat_tls_inbound_packet_process(
	nyoci_t self,
	char* buffer,
	int packet_length
);

//! Called by the platform to dispatch outbound DTLS packets.
NYOCI_API_EXTERN nyoci_status_t nyoci_plat_tls_outbound_packet_process(
	nyoci_t self,
	const uint8_t* data_ptr,
	int data_len
);

#endif // NYOCI_nyoci_plat_tls_h
