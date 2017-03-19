/*	@file nyoci-plat-openssl.c
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

#if HAVE_CONFIG_H
#include <config.h>
#endif

//#define VERBOSE_DEBUG 1
//#define DEBUG 1

#include "assert-macros.h"

#include "libnyoci.h"

#include "nyoci-plat-tls.h"

#include "nyoci-internal.h"
#include "nyoci-logging.h"

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <netdb.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/cdefs.h>
#include <time.h>
#include <sys/select.h>
#include <poll.h>

#define COOKIE_SECRET_LENGTH 16
unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
int cookie_initialized=0;

int
generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
	unsigned char result[EVP_MAX_MD_SIZE];
	unsigned int resultlength;
	HMAC_CTX hmac_ctx;

	/* Initialize a random secret */
	if (!cookie_initialized) {
		if (!RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH)) {
			printf("error setting random cookie secret");
			return 0;
		}
		cookie_initialized = 1;
	}

	HMAC_Init(&hmac_ctx, cookie_secret, COOKIE_SECRET_LENGTH, EVP_sha1());

	HMAC_Update(&hmac_ctx, (const uint8_t*)&nyoci_plat_get_remote_sockaddr()->nyoci_addr, sizeof(nyoci_addr_t));
	HMAC_Update(&hmac_ctx, (const uint8_t*)&nyoci_plat_get_remote_sockaddr()->nyoci_port, 2);

	HMAC_Update(&hmac_ctx, (const uint8_t*)&nyoci_plat_get_local_sockaddr()->nyoci_addr, sizeof(nyoci_addr_t));
	HMAC_Update(&hmac_ctx, (const uint8_t*)&nyoci_plat_get_local_sockaddr()->nyoci_port, 2);

	/* Calculate HMAC of buffer using the secret */
	HMAC_Final(&hmac_ctx, result, &resultlength);

	memcpy(cookie, result, resultlength);
	*cookie_len = resultlength;

	DEBUG_PRINTF("generate_cookie: Generated a cookie");

	return 1;
}

int
verify_cookie(SSL *ssl, unsigned char *cookie, unsigned int cookie_len)
{
	unsigned char result[EVP_MAX_MD_SIZE];
	unsigned int resultlength;
	HMAC_CTX hmac_ctx;

	DEBUG_PRINTF("verify_cookie: Will verify");

	/* Initialize a random secret */
	if (!cookie_initialized) {
		return 0;
	}

	HMAC_Init(&hmac_ctx, cookie_secret, COOKIE_SECRET_LENGTH, EVP_sha1());

	HMAC_Update(&hmac_ctx, (const uint8_t*)&nyoci_plat_get_remote_sockaddr()->nyoci_addr, sizeof(nyoci_addr_t));
	HMAC_Update(&hmac_ctx, (const uint8_t*)&nyoci_plat_get_remote_sockaddr()->nyoci_port, 2);

	HMAC_Update(&hmac_ctx, (const uint8_t*)&nyoci_plat_get_local_sockaddr()->nyoci_addr, sizeof(nyoci_addr_t));
	HMAC_Update(&hmac_ctx, (const uint8_t*)&nyoci_plat_get_local_sockaddr()->nyoci_port, 2);

	/* Calculate HMAC of buffer using the secret */
	HMAC_Final(&hmac_ctx, result, &resultlength);

	if ( (cookie_len == resultlength)
	  && (memcmp(result, cookie, resultlength) == 0)
	) {
		return 1;
	}

	DEBUG_PRINTF("verify_cookie: VERIFY FAILED");

	return 0;
}


int
dtls_verify_callback (int ok, X509_STORE_CTX *ctx)
{
	/* This function should ask the user
	 * if he trusts the received certificate.
	 * Here we always trust.
	 */
	DEBUG_PRINTF("dtls_verify_callback: Called!");
	return 1;
}

static bt_compare_result_t
nyoci_openssl_session_compare(
	const void* lhs_, const void* rhs_, void* context
) {
	const struct nyoci_openssl_session_s* lhs = (struct nyoci_openssl_session_s*)lhs_;
	const struct nyoci_openssl_session_s* rhs = (struct nyoci_openssl_session_s*)rhs_;
	int ret;

	ret = memcmp(&lhs->sockaddr_remote.nyoci_addr, &rhs->sockaddr_remote.nyoci_addr, sizeof(nyoci_addr_t));

	if (ret != 0) {
		return ret > 0 ? 1 : -1;
	}

	ret = (int)lhs->sockaddr_remote.nyoci_port - (int)rhs->sockaddr_remote.nyoci_port;

	if (ret != 0) {
		return ret > 0 ? 1 : -1;
	}

	if ( !NYOCI_IS_ADDR_UNSPECIFIED(&lhs->sockaddr_local.nyoci_addr)
	  && !NYOCI_IS_ADDR_UNSPECIFIED(&rhs->sockaddr_local.nyoci_addr)
	) {
		ret = memcmp(&lhs->sockaddr_local.nyoci_addr, &rhs->sockaddr_local.nyoci_addr, sizeof(nyoci_addr_t));

		if (ret != 0) {
			return ret > 0 ? 1 : -1;
		}
	}

	if ( (lhs->sockaddr_local.nyoci_port != 0)
	  && (rhs->sockaddr_local.nyoci_port != 0)
	) {
		ret = (int)lhs->sockaddr_local.nyoci_port - (int)rhs->sockaddr_local.nyoci_port;

		if (ret != 0) {
			return ret > 0 ? 1 : -1;
		}
	}

	return 0;
}

static bt_compare_result_t
nyoci_openssl_session_compare_current(
	const void* lhs_, const void* rhs_, void* context
) {
	const struct nyoci_openssl_session_s* lhs = (struct nyoci_openssl_session_s*)lhs_;
	const nyoci_sockaddr_t* rhs_remote_sockaddr = nyoci_plat_get_remote_sockaddr();
	const nyoci_sockaddr_t* rhs_local_sockaddr = nyoci_plat_get_local_sockaddr();
	int ret;

	ret = memcmp(&lhs->sockaddr_remote.nyoci_addr, &rhs_remote_sockaddr->nyoci_addr, sizeof(nyoci_addr_t));

	if (ret != 0) {
		return ret > 0 ? 1 : -1;
	}

	ret = (int)lhs->sockaddr_remote.nyoci_port - (int)rhs_remote_sockaddr->nyoci_port;

	if (ret != 0) {
		return ret > 0 ? 1 : -1;
	}

	if ( !NYOCI_IS_ADDR_UNSPECIFIED(&lhs->sockaddr_local.nyoci_addr)
	  && !NYOCI_IS_ADDR_UNSPECIFIED(&rhs_local_sockaddr->nyoci_addr)
	) {
		ret = memcmp(&lhs->sockaddr_local.nyoci_addr, &rhs_local_sockaddr->nyoci_addr, sizeof(nyoci_addr_t));

		if (ret != 0) {
			return ret > 0 ? 1 : -1;
		}
	}

	if ( (lhs->sockaddr_local.nyoci_port != 0)
	  && (rhs_local_sockaddr->nyoci_port != 0)
	) {
		ret = (int)lhs->sockaddr_local.nyoci_port - (int)rhs_local_sockaddr->nyoci_port;

		if (ret != 0) {
			return ret > 0 ? 1 : -1;
		}
	}

	return 0;
}

static void
nyoci_openssl_session_finalize(
	struct nyoci_openssl_session_s* item, nyoci_t context
) {
	if (item->ssl) {
		SSL_shutdown(item->ssl);
		SSL_free(item->ssl);

		if (item == context->plat.ssl.curr_session) {
			context->plat.ssl.curr_session = NULL;
		}
	}

	nyoci_invalidate_timer(context, &item->dtls_timer);

	free(item);
}

static struct nyoci_openssl_session_s*
nyoci_openssl_session_lookup_by_ssl(nyoci_t self, SSL* ssl)
{
	struct nyoci_openssl_session_s* item;

	item = (struct nyoci_openssl_session_s*)bt_first(self->plat.ssl.sessions);

	for (; item; item = (struct nyoci_openssl_session_s*)bt_next(item)) {
		if (item->ssl == ssl) {
			break;
		}
	}

	return item;
}

static struct nyoci_openssl_session_s*
nyoci_openssl_session_lookup_current(nyoci_t self)
{
	return (struct nyoci_openssl_session_s*)bt_find(
		(void**)&self->plat.ssl.sessions,
		NULL,
		(bt_compare_func_t)nyoci_openssl_session_compare_current,
		self
	);
}

/* Uses the current local and remote sockaddr structs */
static SSL*
lookup_current_ssl_object(nyoci_t self) {
	struct nyoci_openssl_session_s* session = nyoci_openssl_session_lookup_current(self);

	if (session) {
		// Splay for improved performance of recent sessions.
		bt_splay(
			(void*)&self->plat.ssl.sessions,
			session
		);

		return session->ssl;
	}

	return NULL;
}

static bool
remove_ssl_object(nyoci_t self, SSL* ssl) {
	struct nyoci_openssl_session_s* item;

	// First we have to find the appropriate session object.
	item = nyoci_openssl_session_lookup_by_ssl(self, ssl);

	if (item) {
		if (bt_remove(
			(void**)&self->plat.ssl.sessions,
			item,
			(bt_compare_func_t)nyoci_openssl_session_compare,
			(bt_delete_func_t)nyoci_openssl_session_finalize,
			self
		)) {
			ssl = NULL;
		}
	}

	if (ssl) {
		SSL_shutdown(ssl);
		SSL_free(ssl);
	}
	return false;
}

static void
nyoci_openssl_session_update_timeout(struct nyoci_openssl_session_s* item, nyoci_t nyoci)
{
	struct timeval timeout = { -1, -1 };
	DTLSv1_get_timeout(item->ssl, &timeout);
	if (timeout.tv_sec != -1 || timeout.tv_usec != -1) {
		nyoci_cms_t cms = (nyoci_cms_t)(timeout.tv_sec * MSEC_PER_SEC) + (nyoci_cms_t)(timeout.tv_usec / USEC_PER_MSEC);
		nyoci_schedule_timer(
			nyoci,
			&item->dtls_timer,
			cms
		);
	}
}

static bool
handle_ssl_outbound_traffic(nyoci_t self, SSL* ssl)
{
	bool ret = false;
	if (SSL_in_connect_init(ssl)) {
		int err = SSL_connect(ssl);

		if (err <= 0) {
			switch (SSL_get_error(ssl, err)) {
			case SSL_ERROR_WANT_WRITE:
				DEBUG_PRINTF("SSL connect WANT_WRITE");
				break;

			case SSL_ERROR_WANT_READ:
				DEBUG_PRINTF("SSL connect WANT_READ");
				break;
			default:
				DEBUG_PRINTF("SSL connect error: %s (%d)", ERR_error_string(ERR_peek_last_error(), NULL), (int)SSL_get_error(ssl, err));
				break;
			}
		} else {
			DEBUG_PRINTF("SSL connect CONNECTED!");
		}
	}

	if (BIO_ctrl_pending(SSL_get_wbio(ssl)) > 0) {
		socklen_t outlen;
		uint8_t outbuf[1500];

		// TODO: Writeme!
		/* Read the data out of the for_writing bio */
		outlen = BIO_read(SSL_get_wbio(ssl), outbuf, sizeof(outbuf));

		if (outlen) {
			ssize_t sent_bytes;
			DEBUG_PRINTF("handle_ssl_outbound_traffic: Sending packet with %d bytes", outlen);

			sent_bytes = sendtofrom(
				self->plat.fd_dtls,
				outbuf,
				outlen,
				0,
				(struct sockaddr *)nyoci_plat_get_remote_sockaddr(),
				sizeof(nyoci_sockaddr_t),
				(struct sockaddr *)nyoci_plat_get_local_sockaddr(),
				sizeof(nyoci_sockaddr_t)
			);
			if (sent_bytes < 0) {
				perror("handle_ssl_outbound_traffic");
				DEBUG_PRINTF("handle_ssl_outbound_traffic: SEND FAILED: %s (%d)", strerror(errno), errno);
			} else {
				DEBUG_PRINTF("handle_ssl_outbound_traffic: Sent %d bytes", (int)sent_bytes);
			}
		}
		ret = true;
	}

	return ret;
}

static void
handle_dtls_timer(nyoci_t nyoci, void* context) {
	struct nyoci_openssl_session_s* item = (struct nyoci_openssl_session_s*)context;

	DTLSv1_handle_timeout(item->ssl);
	handle_ssl_outbound_traffic(nyoci, item->ssl);
	nyoci_openssl_session_update_timeout(item, nyoci);

	DEBUG_PRINTF("handle_dtls_timer:exit: SSL State: %s", SSL_state_string_long(item->ssl));
}

static bool
add_ssl_object(nyoci_t self, SSL* ssl, const nyoci_sockaddr_t* local, const nyoci_sockaddr_t* remote) {
	bool ret = false;
	struct nyoci_openssl_session_s* new_item;

	new_item = calloc(sizeof(*new_item), 1);

	if (!new_item) {
		goto bail;
	}

	new_item->ssl = ssl;

	if (remote) {
		new_item->sockaddr_remote = *remote;
	}

	if (local) {
		new_item->sockaddr_local = *local;
	}

	bt_insert(
		(void**)&self->plat.ssl.sessions,
		new_item,
		(bt_compare_func_t)nyoci_openssl_session_compare,
		(bt_delete_func_t)nyoci_openssl_session_finalize,
		self
	);

	new_item->last_activity = new_item->created = nyoci_plat_cms_to_timestamp(0);

	nyoci_timer_init(
		&new_item->dtls_timer,
		&handle_dtls_timer,
		NULL,
		new_item
	);

	ret = true;

bail:
	return ret;
}


void
load_dh_params(SSL_CTX *ctx)
{
	DH *dh=NULL;
	// SECURITY: This whole section needs to be removed or rewritten, these are insecure defaults.

	if(((dh = DH_new()) == NULL) || !DH_generate_parameters_ex(dh, 128, 5, NULL)) {
		DEBUG_PRINTF("Couldn't generate DH");
		return;
	}

	if (!DH_generate_key(dh))  {
		DEBUG_PRINTF("Couldn't generate DH key");
		return;
	}

	if (SSL_CTX_set_tmp_dh(ctx,dh)<0) {
		DEBUG_PRINTF("Couldn't set DH params");
		return;
	}
}

nyoci_status_t
nyoci_plat_tls_set_remote_hostname(const char* hostname)
{
	// TODO: Writeme!
	return NYOCI_STATUS_OK;
}

void*
nyoci_plat_tls_get_context(nyoci_t self) {
	NYOCI_SINGLETON_SELF_HOOK;
	return self->plat.ssl.ssl_ctx;
}

void*
nyoci_plat_tls_get_current_session(void) {
	nyoci_t const self = nyoci_get_current_instance();
	if (self->plat.ssl.curr_session) {
		return self->plat.ssl.curr_session->ssl;
	}
	return NULL;
}

nyoci_status_t
nyoci_plat_tls_set_context(nyoci_t self, void* context) {
	NYOCI_SINGLETON_SELF_HOOK;
	nyoci_status_t ret = NYOCI_STATUS_FAILURE;
	SSL_library_init();
	ERR_load_BIO_strings();
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();

	if (context == NYOCI_PLAT_TLS_DEFAULT_CONTEXT) {
		// Set up a context with reasonable defaults.

		SSL_CTX* ctx;

#if HAVE_OPENSSL_DTLS_METHOD
		ctx = SSL_CTX_new(DTLS_method());
#else
		ctx = SSL_CTX_new(DTLSv1_method());
#endif

		require(ctx != NULL, bail);

		self->plat.ssl.ssl_ctx = ctx;

		// TODO: SECURITY: REMOVE THIS FOR PRODUCTION.
		SSL_CTX_set_cipher_list(ctx, "ALL:NULL:eNULL:aNULL");

		//SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, dtls_verify_callback);
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, dtls_verify_callback);

	} else {
		self->plat.ssl.ssl_ctx = context;
	}

	require(self->plat.ssl.ssl_ctx != NULL, bail);

	// TODO: SECURITY: REMOVE THIS FOR PRODUCTION.
	load_dh_params(self->plat.ssl.ssl_ctx);

	SSL_CTX_set_session_cache_mode(self->plat.ssl.ssl_ctx, SSL_SESS_CACHE_OFF);
	SSL_CTX_set_cookie_generate_cb(self->plat.ssl.ssl_ctx, generate_cookie);
	SSL_CTX_set_cookie_verify_cb(self->plat.ssl.ssl_ctx, verify_cookie);

	ret = NYOCI_STATUS_OK;
bail:
	return ret;
}

nyoci_status_t
nyoci_plat_tls_inbound_packet_process(
	nyoci_t self,
	char* buffer,
	int len
) {
	NYOCI_SINGLETON_SELF_HOOK;
	nyoci_status_t ret = NYOCI_STATUS_FAILURE;
	struct nyoci_openssl_session_s* session = NULL;
	SSL* ssl = NULL;
	int err;

	if (NULL == self->plat.ssl.ssl_ctx) {
		ret = NYOCI_STATUS_UNSUPPORTED_URI;
		goto bail;
	}

#if VERBOSE_DEBUG
	{
		char addr_str[50] = "???";
		uint16_t port = ntohs(nyoci_plat_get_remote_sockaddr()->nyoci_port);
		NYOCI_ADDR_NTOP(addr_str,sizeof(addr_str),&nyoci_plat_get_remote_sockaddr()->nyoci_addr);
		DEBUG_PRINTF("nyoci(%p): Inbound DTLS packet from [%s]:%d", self, addr_str, (int)port);
	}
#endif

	ERR_remove_state(0);

	self->plat.ssl.curr_session = session = nyoci_openssl_session_lookup_current(self);
	if (session) {
		ssl = session->ssl;
	}

	if (!session) {
		DEBUG_PRINTF("nyoci_plat_tls_inbound_packet_process: *** Inbound packet from unknown session!");

		// Packet for an as-of-yet uncreated session
		if (!self->plat.ssl.next_ssl) {
			BIO* bio_r = BIO_new(BIO_s_mem());
			BIO* bio_w = BIO_new(BIO_s_mem());

			BIO_set_mem_eof_return(bio_r, -1);
			BIO_set_mem_eof_return(bio_w, -1);

			self->plat.ssl.next_ssl = SSL_new(self->plat.ssl.ssl_ctx);

			require(self->plat.ssl.next_ssl != NULL, bail);

			SSL_set_bio(
				self->plat.ssl.next_ssl,
				bio_r,
				bio_w
			);

			SSL_set_mode(self->plat.ssl.next_ssl, SSL_MODE_AUTO_RETRY);
			SSL_set_accept_state(self->plat.ssl.next_ssl);

#if 1
			SSL_set_options(self->plat.ssl.next_ssl, SSL_OP_COOKIE_EXCHANGE);
#else
			DTLSv1_listen(self->plat.ssl.next_ssl, (void*)nyoci_plat_get_remote_sockaddr());
#endif
		}
		ssl = self->plat.ssl.next_ssl;

		BIO_write(SSL_get_rbio(ssl), buffer, len);

		err = SSL_accept(ssl);

		if (err > 0) {
			DEBUG_PRINTF("nyoci_plat_tls_inbound_packet_process: New secure connection!");
			// New secure connection!
			// Pass off this SSL object into the list
			// of currently active SSL objects.

			if (add_ssl_object(
				self,
				ssl,
				nyoci_plat_get_local_sockaddr(),
				nyoci_plat_get_remote_sockaddr()
			) != true) {
				// We were unable to add the SSL object for
				// some reason. Clean it up so we don't leak.
				SSL_shutdown(ssl);
				handle_ssl_outbound_traffic(self, ssl);
				SSL_free(ssl);
				ssl = NULL;
			}

			self->plat.ssl.curr_session = session = nyoci_openssl_session_lookup_current(self);

			// NULL out this SSL object so that a new one
			// will be created later.
			self->plat.ssl.next_ssl = NULL;
		} else {
			switch (SSL_get_error(ssl, err)) {
			case SSL_ERROR_WANT_WRITE:
				DEBUG_PRINTF("DTLS listen WANT_WRITE");
				ret = NYOCI_STATUS_OK;
				break;
			case SSL_ERROR_WANT_READ:
				DEBUG_PRINTF("DTLS listen WANT_READ");
				ret = NYOCI_STATUS_OK;
				break;
			case SSL_ERROR_SSL:
			default:
				DEBUG_PRINTF("DTLS listen error: %s (%d)", ERR_error_string(ERR_peek_last_error(), NULL), (int)SSL_get_error(ssl, err));
				handle_ssl_outbound_traffic(self, ssl);
				SSL_free(ssl);
				ssl = self->plat.ssl.next_ssl = NULL;
				ret = NYOCI_STATUS_FAILURE;
				break;
			}
			goto bail;
		}

	} else {
		DEBUG_PRINTF("nyoci_plat_tls_inbound_packet_process: *** Inbound packet from KNOWN session!");
		BIO_write(SSL_get_rbio(ssl), buffer, len);

		if (0 != (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN)) {
			ret = NYOCI_STATUS_SESSION_CLOSED;
			goto bail;
		}
	}

	if (ssl) {
		len = SSL_read(ssl, buffer, len);

		if (SSL_get_error(ssl, len) == SSL_ERROR_WANT_WRITE) {
			handle_ssl_outbound_traffic(self, ssl);
			len = SSL_read(ssl, buffer, len);
		}

		switch (SSL_get_error(ssl, len)) {
		case SSL_ERROR_NONE:
		case SSL_ERROR_WANT_WRITE:
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_ZERO_RETURN:
			ret = NYOCI_STATUS_OK;
			break;

		default:
		case SSL_ERROR_SSL:
			ret = NYOCI_STATUS_SESSION_ERROR;
			DEBUG_PRINTF("SSL read error: %s (%d)", ERR_error_string(ERR_peek_last_error(), NULL), (int)SSL_get_error(ssl, len));
			break;
		}

		if (ret) {
			goto bail;
		}

		if (len > 0) {
			ret = nyoci_inbound_packet_process(self, buffer, (coap_size_t)len, 0);
		}
		goto bail;
	}

	ret = NYOCI_STATUS_OK;

bail:

	if (ssl) {
		while(handle_ssl_outbound_traffic(self, ssl)) { }
		DEBUG_PRINTF("nyoci_plat_tls_inbound_packet_process:exit: SSL State: %s", SSL_state_string_long(ssl));
	}

	// Update timer
	if (session) {
		nyoci_openssl_session_update_timeout(session, self);
	}

	self->plat.ssl.curr_session = NULL;
	return ret;
}

nyoci_status_t
nyoci_plat_tls_outbound_packet_process(
	nyoci_t self,
	const uint8_t* data_ptr,
	int data_len
) {
	NYOCI_SINGLETON_SELF_HOOK;
	nyoci_status_t ret = NYOCI_STATUS_FAILURE;
	struct nyoci_openssl_session_s* session = self->plat.ssl.curr_session;
	SSL* ssl = NULL;
	int err;

	if (NULL == self->plat.ssl.ssl_ctx) {
		ret = NYOCI_STATUS_UNSUPPORTED_URI;
		goto bail;
	}

	ERR_remove_state(0);

	if (session) {
		ssl = session->ssl;
	} else {
		// Check the local and remote addresses to see
		// if there is an SSL object already in use.
		self->plat.ssl.curr_session = session = nyoci_openssl_session_lookup_current(self);
		if (session) {
			ssl = session->ssl;
		}
	}

	if (!session) {
		// We don't have a session yet.
		// Kick off a session and get it ready.
		// If there is no SSL object associated with
		// this remote/local pair, then return NYOCI_STATUS_WAIT_FOR_SESSION.

		BIO* bio_r = BIO_new(BIO_s_mem());
		BIO* bio_w = BIO_new(BIO_s_mem());

		BIO_set_mem_eof_return(bio_r, -1);
		BIO_set_mem_eof_return(bio_w, -1);

		ssl = SSL_new(self->plat.ssl.ssl_ctx);

		require(ssl != NULL, bail);

		SSL_set_bio(ssl, bio_r, bio_w);

		SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

		SSL_set_connect_state(ssl);

		if (add_ssl_object(
			self,
			ssl,
			nyoci_plat_get_local_sockaddr(),
			nyoci_plat_get_remote_sockaddr()
		) != true) {
			// We were unable to add the SSL object for
			// some reason.
			ret = NYOCI_STATUS_SESSION_ERROR;
			goto bail;
		}
		ret = NYOCI_STATUS_WAIT_FOR_SESSION;

		self->plat.ssl.curr_session = session = nyoci_openssl_session_lookup_current(self);
	}

	session->last_activity = nyoci_plat_cms_to_timestamp(0);
	session->msg_id = self->outbound.packet->msg_id;

	{
		socklen_t len;
		// If the session is in an error state, then return
		// NYOCI_STATUS_SESSION_ERROR and clean up the session.

		if (0 != (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN)) {
			ret = NYOCI_STATUS_SESSION_CLOSED;
			goto bail;
		}

		len = SSL_write(ssl, data_ptr, data_len);

		if (SSL_get_error(ssl, len) == SSL_ERROR_WANT_WRITE) {
			handle_ssl_outbound_traffic(self, ssl);
			len = SSL_write(ssl, data_ptr, data_len);
		}

		switch (SSL_get_error(ssl, len)) {
			case SSL_ERROR_NONE:
				ret = NYOCI_STATUS_OK;
				break;

			case SSL_ERROR_WANT_WRITE:
				DEBUG_PRINTF("nyoci_plat_tls_outbound_packet_process: SSL write WANT_WRITE");
				ret = NYOCI_STATUS_WAIT_FOR_SESSION;
				break;

			case SSL_ERROR_WANT_READ:
				DEBUG_PRINTF("nyoci_plat_tls_outbound_packet_process: SSL write WANT_READ");
				ret = NYOCI_STATUS_WAIT_FOR_SESSION;
				break;

			case SSL_ERROR_SYSCALL:
				ret = NYOCI_STATUS_SESSION_ERROR;
				DEBUG_PRINTF("SYSCALL write error: %s (%d)", ERR_error_string(ERR_peek_last_error(), NULL), (int)ERR_peek_last_error());
				SSL_shutdown(ssl);
				goto bail;

			case SSL_ERROR_SSL:
			default:
				ret = NYOCI_STATUS_SESSION_ERROR;
				DEBUG_PRINTF("SSL write error: %s (%d)", ERR_error_string(ERR_peek_last_error(), NULL), (int)SSL_get_error(ssl, len));
				SSL_shutdown(ssl);
				goto bail;
		}
	}

bail:
	if ( (ssl != NULL)
	  && (NYOCI_STATUS_SESSION_ERROR == ret || NYOCI_STATUS_SESSION_CLOSED == ret)
	) {
		remove_ssl_object(self, ssl);
		ssl = NULL;
		session = NULL;
	}

	// Send any needed outbound packets.
	if (ssl) {
		while(handle_ssl_outbound_traffic(self, ssl)) { }
		DEBUG_PRINTF("nyoci_plat_tls_outbound_packet_process:exit: SSL State: %s", SSL_state_string_long(ssl));
	}

	// Update timer
	if (session) {
		nyoci_openssl_session_update_timeout(session, self);
	}

	return ret;
}
