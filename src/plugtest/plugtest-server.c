/*	@file plugtest-server.c
**	@author Robert Quattlebaum <darco@deepdarc.com>
**	@desc Plugtest Server Object
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

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <libnyoci/libnyoci.h>
#include "plugtest-server.h"

#include <libnyoci/nyoci-missing.h>
#include <libnyoci/string-utils.h> // For uint32_to_dec_cstr()

#if CONTIKI && !defined(time)
#define time(x)		clock_seconds()
#endif

#define PLUGTEST_OBS_KEY			(42)

nyoci_status_t
plugtest_test_handler(nyoci_node_t node)
{
	nyoci_status_t ret = NYOCI_STATUS_NOT_ALLOWED;
	char* content = NULL;
	coap_size_t max_len = 0;
	coap_code_t method = nyoci_inbound_get_code();

	if(method==COAP_METHOD_GET) {
		ret = nyoci_outbound_begin_response(COAP_RESULT_205_CONTENT);
	} else if(method==COAP_METHOD_POST) {
		ret = nyoci_outbound_begin_response(COAP_RESULT_201_CREATED);
	} else if(method==COAP_METHOD_PUT) {
		ret = nyoci_outbound_begin_response(COAP_RESULT_204_CHANGED);
	} else if(method==COAP_METHOD_DELETE) {
		ret = nyoci_outbound_begin_response(COAP_RESULT_202_DELETED);
	}

	if(ret) goto bail;

	nyoci_outbound_add_option_uint(COAP_OPTION_CONTENT_TYPE, COAP_CONTENT_TYPE_TEXT_PLAIN);

	content = nyoci_outbound_get_content_ptr(&max_len);
	if(!content) {
		ret = NYOCI_STATUS_FAILURE;
		goto bail;
	}

	nyoci_inbound_get_path(content, NYOCI_GET_PATH_LEADING_SLASH|NYOCI_GET_PATH_INCLUDE_QUERY);
	strlcat(content,"\nPlugtest!\nMethod = ",max_len);
	strlcat(content,coap_code_to_cstr(method),max_len);
	strlcat(content,"\n",max_len);

	{
		const uint8_t* value;
		coap_size_t value_len;
		coap_option_key_t key;
		while((key=nyoci_inbound_next_option(&value, &value_len))!=COAP_OPTION_INVALID) {
			strlcat(content,coap_option_key_to_cstr(key,1),max_len);
			strlcat(content,": ",max_len);
			if(coap_option_value_is_string(key)) {
				coap_size_t argh = (coap_size_t)strlen(content) + value_len;
				strlcat(content,(char*)value,MIN(max_len,argh+1));
				content[argh] = 0;
			} else {
				strlcat(content,"<binary>",max_len);
			}
			strlcat(content,"\n",max_len);
		}
	}

	nyoci_outbound_set_content_len((coap_size_t)strlen(content));

	ret = nyoci_outbound_send();

bail:
	return ret;
}

nyoci_status_t
plugtest_separate_async_resend_response(void* context)
{
	nyoci_status_t ret = 0;
	struct nyoci_async_response_s* async_response = (void*)context;

#if !NYOCI_AVOID_PRINTF || VERBOSE_DEBUG
	printf("Resending async response. . . %p\n",async_response);
#endif

	ret = nyoci_outbound_begin_async_response(COAP_RESULT_205_CONTENT,async_response);
	require_noerr(ret,bail);

	ret = nyoci_outbound_add_option_uint(COAP_OPTION_CONTENT_TYPE, COAP_CONTENT_TYPE_TEXT_PLAIN);
	require_noerr(ret,bail);

	ret = nyoci_outbound_append_content("This was an asynchronous response!",NYOCI_CSTR_LEN);
	require_noerr(ret,bail);

	ret = nyoci_outbound_send();
	require_noerr(ret,bail);

bail:
	return ret;
}

nyoci_status_t
plugtest_separate_async_ack_handler(int statuscode, void* context) {
	struct nyoci_async_response_s* async_response = (void*)context;

#if !NYOCI_AVOID_PRINTF || VERBOSE_DEBUG
	printf("Finished sending async response. code=%d async_response=%p\n",statuscode,async_response);
#endif
	if(statuscode == NYOCI_STATUS_TRANSACTION_INVALIDATED) {
		nyoci_finish_async_response(async_response);
		free(async_response);
	}

	return NYOCI_STATUS_OK;
}

nyoci_status_t
plugtest_separate_handler(
	nyoci_node_t		node
) {
	struct nyoci_async_response_s* async_response = NULL;
	nyoci_transaction_t transaction = NULL;
	nyoci_status_t ret = NYOCI_STATUS_NOT_ALLOWED;
	coap_code_t method = nyoci_inbound_get_code();

	if(method==COAP_METHOD_GET) {
		if(nyoci_inbound_is_dupe()) {
			nyoci_outbound_begin_response(COAP_CODE_EMPTY);
			nyoci_outbound_send();
			ret = NYOCI_STATUS_OK;
			goto bail;
		}

		async_response = calloc(sizeof(struct nyoci_async_response_s),1);
		if(!async_response) {
			ret = NYOCI_STATUS_MALLOC_FAILURE;
			goto bail;
		}

#if !NYOCI_AVOID_PRINTF || VERBOSE_DEBUG
		printf("This request needs an async response. %p\n",async_response);
#endif

		transaction = nyoci_transaction_init(
			transaction,
			NYOCI_TRANSACTION_DELAY_START|NYOCI_TRANSACTION_ALWAYS_INVALIDATE,
			&plugtest_separate_async_resend_response,
			&plugtest_separate_async_ack_handler,
			(void*)async_response
		);
		if(!transaction) {
			free(async_response);
			// TODO: Consider dropping instead...?
			ret = NYOCI_STATUS_MALLOC_FAILURE;
			goto bail;
		}

		ret = nyoci_transaction_begin(
			nyoci_get_current_instance(),
			transaction,
			(nyoci_inbound_get_packet()->tt==COAP_TRANS_TYPE_CONFIRMABLE)?(nyoci_cms_t)(COAP_MAX_TRANSMIT_WAIT*MSEC_PER_SEC):1
		);
		if(NYOCI_STATUS_OK != ret) {
			nyoci_transaction_end(nyoci_get_current_instance(),transaction);
			goto bail;
		}

		ret = nyoci_start_async_response(async_response,0);
		if(ret) { goto bail; }

		async_response = NULL;
	}

bail:
	return ret;
}

void
plugtest_obs_timer_callback(nyoci_t nyoci, void* context) {
	struct plugtest_server_s *self = (void*)context;

	nyoci_invalidate_timer(nyoci,&self->obs_timer);
	nyoci_schedule_timer(nyoci,&self->obs_timer,5 * MSEC_PER_SEC);

	nyoci_observable_trigger(&self->observable,PLUGTEST_OBS_KEY,0);
}

nyoci_status_t
plugtest_obs_handler(
	struct plugtest_server_s *self
) {
	nyoci_status_t ret = NYOCI_STATUS_NOT_ALLOWED;
	coap_code_t method = nyoci_inbound_get_code();
	uint32_t now = (uint32_t)time(NULL);

	if (method == COAP_METHOD_GET) {
		char* content = NULL;
		coap_size_t max_len = 0;

		ret = nyoci_outbound_begin_response(COAP_RESULT_205_CONTENT);
		require_noerr(ret, bail);

		ret = nyoci_outbound_add_option_uint(COAP_OPTION_ETAG, now);
		require_noerr(ret, bail);

		ret = nyoci_outbound_add_option_uint(COAP_OPTION_CONTENT_TYPE, COAP_CONTENT_TYPE_TEXT_PLAIN);
		require_noerr(ret, bail);

		if (!nyoci_timer_is_scheduled(nyoci_get_current_instance(), &self->obs_timer)) {
			plugtest_obs_timer_callback(nyoci_get_current_instance(),self);
		}

		ret = nyoci_observable_update(&self->observable, PLUGTEST_OBS_KEY);
		check_noerr(ret);

		ret = nyoci_outbound_add_option_uint(COAP_OPTION_MAX_AGE, 10);
		require_noerr(ret, bail);

		content = nyoci_outbound_get_content_ptr(&max_len);
		require_action(content!=NULL, bail, ret = NYOCI_STATUS_FAILURE);

		require_action(max_len>11, bail, ret = NYOCI_STATUS_MESSAGE_TOO_BIG);

		ret = nyoci_outbound_set_content_len(
			(coap_size_t)strlen(uint32_to_dec_cstr(content, now))
		);
		require_noerr(ret, bail);

		ret = nyoci_outbound_send();
		require_noerr(ret, bail);
	}
bail:
	return ret;
}

nyoci_status_t
plugtest_large_handler(
	nyoci_node_t		node
) {
	nyoci_status_t ret = NYOCI_STATUS_NOT_ALLOWED;
	char* content = NULL;
	coap_size_t max_len = 0;
	coap_code_t method = nyoci_inbound_get_code();
	uint32_t block_option = 0x03;
	uint32_t block_start = 0;
	uint32_t block_stop = 0;
	uint32_t resource_length = 2000;

	if(method==COAP_METHOD_GET) {
		ret = 0;
	}

	require_noerr(ret,bail);

	{
		const uint8_t* value;
		coap_size_t value_len;
		coap_option_key_t key;
		while((key=nyoci_inbound_next_option(&value, &value_len))!=COAP_OPTION_INVALID) {
			if(key == COAP_OPTION_BLOCK2) {
				uint8_t i;
				block_option = 0;
				for(i = 0; i < value_len; i++)
					block_option = (block_option << 8) + value[i];
			}
		}
	}

	ret = nyoci_outbound_begin_response(COAP_RESULT_205_CONTENT);
	require_noerr(ret,bail);

	ret = nyoci_outbound_add_option_uint(COAP_OPTION_CONTENT_TYPE, COAP_CONTENT_TYPE_TEXT_PLAIN);
	require_noerr(ret,bail);

	ret = nyoci_outbound_add_option_uint(COAP_OPTION_MAX_AGE,60*60);
	require_noerr(ret,bail);

	max_len = nyoci_outbound_get_space_remaining()-2;

	// Here we are making sure our data will fit,
	// and adjusting our block-option size accordingly.
	do {
		struct coap_block_info_s block_info;
		coap_decode_block(&block_info, block_option);
		block_start = block_info.block_offset;
		block_stop = block_info.block_offset + block_info.block_size;

		if(max_len<(block_stop-block_start) && block_option!=0 && !block_info.block_offset) {
			block_option--;
			block_stop = 0;
			continue;
		}
	} while(0==block_stop);

	require_action(block_start<resource_length,bail,ret=NYOCI_STATUS_INVALID_ARGUMENT);

	if(block_stop>=resource_length)
		block_option &= ~(1<<3);
	else
		block_option |= (1<<3);

	ret = nyoci_outbound_add_option_uint(COAP_OPTION_BLOCK2,block_option);
	require_noerr(ret,bail);

	content = nyoci_outbound_get_content_ptr(&max_len);

	require_action(NULL!=content, bail, ret = NYOCI_STATUS_FAILURE);
	require_action(max_len>(block_stop-block_start), bail, ret = NYOCI_STATUS_MESSAGE_TOO_BIG);

	{
		uint32_t i;
		for(i=block_start;i<block_stop;i++) {
			if(!((i+1)%64))
				content[i-block_start] = '\n';
			else
				content[i-block_start] = '0'+(i%10);
		}
	}

	ret = nyoci_outbound_set_content_len((coap_size_t)MIN(block_stop-block_start,resource_length-block_start));
	if(ret) goto bail;

	ret = nyoci_outbound_send();

bail:
	return ret;
}

/*
// Not yet implemented.

nyoci_status_t
plugtest_large_update_handler(
	nyoci_node_t		node
) {
	nyoci_status_t ret = NYOCI_STATUS_NOT_ALLOWED;

	// TODO: Writeme!

bail:
	return ret;
}

nyoci_status_t
plugtest_large_create_handler(
	nyoci_node_t		node
) {
	nyoci_status_t ret = NYOCI_STATUS_NOT_ALLOWED;

	// TODO: Writeme!

bail:
	return ret;
}
*/

nyoci_status_t
plugtest_server_init(struct plugtest_server_s *self,nyoci_node_t root) {

	memset(self,0,sizeof(*self));

	nyoci_node_init(&self->test,root,"test");
	self->test.request_handler = (nyoci_callback_func)&plugtest_test_handler;

	nyoci_node_init(&self->seg1,root,"seg1");
	nyoci_node_init(&self->seg2,&self->seg1,"seg2");
	nyoci_node_init(&self->seg3,&self->seg2,"seg3");
	self->seg3.request_handler = (nyoci_callback_func)&plugtest_test_handler;

	nyoci_node_init(&self->separate,root,"separate");
	self->separate.request_handler = (nyoci_callback_func)&plugtest_separate_handler;

	nyoci_node_init(&self->query,root,"query");
	self->query.request_handler = (nyoci_callback_func)&plugtest_test_handler;

	nyoci_node_init(&self->large,root,"large");
	self->large.request_handler = (nyoci_callback_func)&plugtest_large_handler;

/*
	// Not yet implemented.
	nyoci_node_init(&self->large_update,root,"large_update");
	self->large_update.request_handler = &plugtest_large_update_handler;

	nyoci_node_init(&self->large_create,root,"large_create");
	self->large_create.request_handler = &plugtest_large_create_handler;
*/

	nyoci_node_init(&self->obs,root,"obs");
	self->obs.request_handler = (nyoci_callback_func)&plugtest_obs_handler;
	self->obs.context = (void*)self;
	self->obs.is_observable = true;

	nyoci_timer_init(&self->obs_timer,&plugtest_obs_timer_callback,NULL,(void*)self);

	return NYOCI_STATUS_OK;
}
