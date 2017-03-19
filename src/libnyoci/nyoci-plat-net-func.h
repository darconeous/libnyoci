/*!	@file nyoci-plat.h
**	@author Robert Quattlebaum <darco@deepdarc.com>
**	@brief Platfom-defined methods
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

#ifndef NYOCI_PLAT_HEADER_INCLUDED
#define NYOCI_PLAT_HEADER_INCLUDED 1

#if !defined(NYOCI_INCLUDED_FROM_LIBNYOCI_H) && !defined(BUILDING_LIBNYOCI)
#error "Do not include this header directly, include <libnyoci/libnyoci.h> instead"
#endif

#ifndef DOXYGEN_SHOULD_SKIP_THIS

#if NYOCI_SINGLETON
#define nyoci_plat_get_port(self)		nyoci_plat_get_port()
#define nyoci_plat_init(self)		nyoci_plat_init()
#define nyoci_plat_finalize(self)		nyoci_plat_finalize()
#define nyoci_plat_get_fd(self)		nyoci_plat_get_fd()
#define nyoci_plat_process(self)		nyoci_plat_process()
#define nyoci_plat_join_standard_groups(self, ...)	nyoci_plat_join_standard_groups(__VA_ARGS__)
#define nyoci_plat_wait(self,...)		nyoci_plat_wait(__VA_ARGS__)
#define nyoci_plat_outbound_start(self,...)		nyoci_plat_outbound_start(__VA_ARGS__)
#define nyoci_plat_outbound_finish(self,...)		nyoci_plat_outbound_finish(__VA_ARGS__)
#define nyoci_plat_bind_to_port(self,...)		nyoci_plat_bind_to_port(__VA_ARGS__)
#define nyoci_plat_bind_to_sockaddr(self,...)		nyoci_plat_bind_to_sockaddr(__VA_ARGS__)
#define nyoci_plat_multicast_join(self,...)		nyoci_plat_multicast_join(__VA_ARGS__)
#define nyoci_plat_multicast_leave(self,...)		nyoci_plat_multicast_leave(__VA_ARGS__)
#define nyoci_plat_update_pollfds(self,...)		nyoci_plat_update_pollfds(__VA_ARGS__)
#endif

#endif

/*!	@addtogroup nyoci
**	@{
*/

NYOCI_BEGIN_C_DECLS


/*!	@defgroup nyoci-plat Platform API
**	@{
*/

/*!	## Defining New Platforms ##
**
**	Platforms have two header files, one for the public API (Called
**	something like `nyoci-plat-bsd.h`, for example) and one for the
**	internal API (Called something like `nyoci-plat-bsd-internal.h`).
**	These files are analogous to `nyoci.h` and `nyoci-internal.h`---they
**	describe both the external user-facing interface and the internal
**	under-the-hood implementation details.
**
**	To implement a new platform, the following methods must be implemented:
**
**	* nyoci_plat_init()
**	* nyoci_plat_finalize()
**	* nyoci_plat_lookup_hostname()
**	* nyoci_plat_bind_to_sockaddr()
**	* nyoci_plat_bind_to_port()
**	* nyoci_plat_cms_to_timestamp()
**	* nyoci_plat_timestamp_to_cms()
**	* nyoci_plat_timestamp_diff()
**	* nyoci_plat_get_session_type()
**	* nyoci_plat_set_session_type()
**	* nyoci_plat_get_remote_sockaddr()
**	* nyoci_plat_get_local_sockaddr()
**	* nyoci_plat_set_remote_sockaddr()
**	* nyoci_plat_set_local_sockaddr()
**	* nyoci_plat_outbound_start()
**	* nyoci_plat_outbound_send_packet()
**
**	Any data that you need to associate with an instance needs to
**	be stored in the struct `nyoci_plat_s`, defined in the internal
**	platform-specific header:
**
**	* struct nyoci_plat_s {}
**
**	Optionally, if the platform supports simplified run-loops you should also
**	implement:
**
**	* nyoci_plat_process()
**	* nyoci_plat_wait()
**
**	Optionally, if the platform supports unix file descriptors, you may want
**	to also implement:
**
**	* nyoci_plat_update_pollfds()
**	* nyoci_plat_update_fdsets()
**
*/

// MARK: -
// MARK: Async IO

/*!	@addtogroup nyoci-asyncio
**	@{
*/

//!	Processes one event or inbound packet (if available).
/*!	This function must be called periodically for LibNyoci to
**	handle events and packets.
*/
NYOCI_API_EXTERN nyoci_status_t nyoci_plat_process(nyoci_t self);

//!	Block until nyoci_plat_process() should be called.
/*! @returns 0 if nyoci_plat_process() should be executed,
**           NYOCI_STATUS_TIMEOUT if the given timeout expired,
**           or an error number if there is some sort of other failure.
**  Some platforms do not implement this function. */
NYOCI_API_EXTERN nyoci_status_t nyoci_plat_wait(nyoci_t self, nyoci_cms_t cms);

/*!	@} */

/*!	@addtogroup nyoci_timer
**	@{
*/

//!< Converts relative time from 'now' into an absolute time.
NYOCI_API_EXTERN nyoci_timestamp_t nyoci_plat_cms_to_timestamp(
	nyoci_cms_t cms //!< [IN] Time from now, in milliseconds
);

NYOCI_API_EXTERN nyoci_cms_t nyoci_plat_timestamp_to_cms(nyoci_timestamp_t timestamp);

NYOCI_API_EXTERN nyoci_cms_t nyoci_plat_timestamp_diff(nyoci_timestamp_t lhs, nyoci_timestamp_t rhs);

/*!	@} */

//! Returns the current listening port of the instance in host order.
/*! This function will likely be DEPRECATED in the future */
NYOCI_API_EXTERN uint16_t nyoci_plat_get_port(nyoci_t self);

NYOCI_API_EXTERN nyoci_status_t nyoci_plat_bind_to_sockaddr(
	nyoci_t self,
	nyoci_session_type_t type,
	const nyoci_sockaddr_t* sockaddr
);

NYOCI_API_EXTERN nyoci_status_t nyoci_plat_bind_to_port(
	nyoci_t self,
	nyoci_session_type_t type,
	uint16_t port
);

#define NYOCI_ANY_INTERFACE		0

NYOCI_API_EXTERN nyoci_status_t nyoci_plat_join_standard_groups(nyoci_t self, int interface);

NYOCI_API_EXTERN void nyoci_plat_set_remote_sockaddr(const nyoci_sockaddr_t* addr);
NYOCI_API_EXTERN void nyoci_plat_set_local_sockaddr(const nyoci_sockaddr_t* addr);
NYOCI_API_EXTERN nyoci_status_t nyoci_plat_set_remote_hostname_and_port(const char* hostname, uint16_t port);
NYOCI_API_EXTERN void nyoci_plat_set_session_type(nyoci_session_type_t type);

NYOCI_API_EXTERN nyoci_status_t nyoci_plat_multicast_join(nyoci_t self, const nyoci_sockaddr_t *group, int interface);
NYOCI_API_EXTERN nyoci_status_t nyoci_plat_multicast_leave(nyoci_t self, const nyoci_sockaddr_t *group, int interface);

//!	Gets a pointer to the sockaddr of the remote machine for the current packet.
NYOCI_API_EXTERN const nyoci_sockaddr_t* nyoci_plat_get_remote_sockaddr(void);

//!	Gets a pointer to the sockaddr of the local socket for the current packet.
NYOCI_API_EXTERN const nyoci_sockaddr_t* nyoci_plat_get_local_sockaddr(void);

//!	Gets the session type for the current packet.
NYOCI_API_EXTERN nyoci_session_type_t nyoci_plat_get_session_type(void);

struct pollfd;

//! Support for `poll()` style asynchronous operation
NYOCI_API_EXTERN int nyoci_plat_update_pollfds(
	nyoci_t self,
	struct pollfd *fds,
	int maxfds
);

#define NYOCI_LOOKUP_HOSTNAME_FLAG_DEFAULT			0
#define NYOCI_LOOKUP_HOSTNAME_FLAG_IPV6_ONLY			(1<<0)
#define NYOCI_LOOKUP_HOSTNAME_FLAG_IPV4_ONLY			(1<<1)
#define NYOCI_LOOKUP_HOSTNAME_FLAG_NUMERIC			(1<<2)

NYOCI_INTERNAL_EXTERN nyoci_status_t nyoci_plat_lookup_hostname(const char* hostname, nyoci_sockaddr_t* sockaddr, int flags);
NYOCI_INTERNAL_EXTERN nyoci_status_t nyoci_plat_outbound_start(nyoci_t self, uint8_t** data_ptr, coap_size_t *data_len);
NYOCI_INTERNAL_EXTERN nyoci_status_t nyoci_plat_outbound_finish(nyoci_t self, const uint8_t* data_ptr, coap_size_t data_len, int flags);

/*!	@} */

/*!	@} */

NYOCI_END_C_DECLS

#endif /* NYOCI_PLAT_HEADER_INCLUDED */
