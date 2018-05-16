/*	@file nyoci_node.c
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

#ifndef VERBOSE_DEBUG
#define VERBOSE_DEBUG 0
#endif

#include "assert-macros.h"
#include "libnyoci.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "ll.h"
#include "url-helpers.h"

#include "libnyoci.h"
#include "nyoci-missing.h"
#include "nyoci-node-router.h"
#include "nyoci-helpers.h"
#include "nyoci-logging.h"
#include "nyoci-internal.h"

// MARK: -
// MARK: Globals

#if NYOCI_AVOID_MALLOC
static struct nyoci_node_s nyoci_node_pool[NYOCI_CONF_MAX_ALLOCED_NODES];
#endif

// MARK: -

static nyoci_status_t
nyoci_default_request_handler(
   nyoci_node_t node
) {
   if(nyoci_inbound_get_code() == COAP_METHOD_GET) {
	   return nyoci_node_list_request_handler(node);
   }
   return NYOCI_STATUS_NOT_FOUND;
}

nyoci_status_t
nyoci_node_router_handler(void* context)
{
	nyoci_request_handler_func handler = NULL;
	nyoci_node_route(context, &handler, &context);
	if(!handler) {
		return NYOCI_STATUS_NOT_IMPLEMENTED;
	}
	return (*handler)(context);
}

nyoci_status_t
nyoci_node_route(nyoci_node_t node, nyoci_request_handler_func* func, void** context) {
	nyoci_status_t ret = 0;
	nyoci_t const self = nyoci_get_current_instance();

	nyoci_inbound_reset_next_option();

	{
		// TODO: Rewrite this to be more efficient.
		const uint8_t* prev_option_ptr = self->inbound.this_option;
		coap_option_key_t prev_key = 0;
		coap_option_key_t key;
		const uint8_t* value;
		coap_size_t value_len;
		while ((key = nyoci_inbound_next_option(&value, &value_len)) != COAP_OPTION_INVALID) {
			if (key > COAP_OPTION_URI_PATH) {
				self->inbound.this_option = prev_option_ptr;
				self->inbound.last_option_key = prev_key;
				break;
			} else if (key == COAP_OPTION_URI_PATH) {
				nyoci_node_t next = nyoci_node_find(
					node,
					(const char*)value,
					(int)value_len
				);
				if (next) {
					node = next;
				} else {
					self->inbound.this_option = prev_option_ptr;
					self->inbound.last_option_key = prev_key;
					break;
				}
			} else if(key==COAP_OPTION_URI_HOST) {
				// Skip host at the moment,
				// because we don't do virtual hosting yet.
			} else if(key==COAP_OPTION_URI_PORT) {
				// Skip port at the moment,
				// because we don't do virtual hosting yet.
			} else if(key==COAP_OPTION_PROXY_URI) {
				// Skip the proxy URI for now.
			} else if(key==COAP_OPTION_CONTENT_TYPE) {
				// Skip.
			} else {
				if(COAP_OPTION_IS_CRITICAL(key)) {
					ret=NYOCI_STATUS_BAD_OPTION;
					assert_printf("Unrecognized option %d, \"%s\"",
						key,
						coap_option_key_to_cstr(key, false)
					);
					goto bail;
				}
			}
			prev_option_ptr = self->inbound.this_option;
			prev_key = self->inbound.last_option_key;
		}
	}

	*func = (void*)node->request_handler;
	if(node->context) {
		*context = node->context;
	} else {
		*context = (void*)node;
	}

bail:
	return ret;
}

// MARK: -
// MARK: Node Funcs

static void
nyoci_node_dealloc(nyoci_node_t x) {
#if NYOCI_AVOID_MALLOC
	x->finalize = NULL;
#else
	free(x);
#endif
}

nyoci_node_t
nyoci_node_alloc() {
	nyoci_node_t ret;
#if NYOCI_AVOID_MALLOC
	uint8_t i;
	for(i=0;i<NYOCI_CONF_MAX_ALLOCED_NODES;i++) {
		ret = &nyoci_node_pool[i];
		if(ret->finalize) {
			ret = NULL;
			continue;
		}
		break;
	}
#else
	ret = (nyoci_node_t)calloc(sizeof(struct nyoci_node_s), 1);
#endif
	if(ret) {
		ret->finalize = &nyoci_node_dealloc;
	} else {
		DEBUG_PRINTF("%s: Malloc failure...?",__func__);
	}
	return ret;
}

#if NYOCI_NODE_ROUTER_USE_BTREE

bt_compare_result_t
nyoci_node_compare(
	nyoci_node_t lhs, nyoci_node_t rhs
) {
	if(lhs->name == rhs->name)
		return 0;
	if(!lhs->name)
		return 1;
	if(!rhs->name)
		return -1;
	return (bt_compare_result_t)strcmp(lhs->name, rhs->name);
}
#endif

static bt_compare_result_t
nyoci_node_ncompare_cstr(
	nyoci_node_t lhs, const char* rhs, intptr_t len
) {
	bt_compare_result_t ret;

	if (lhs->name == rhs) {
		return 0;
	}
	if (!lhs->name) {
		return 1;
	}
	if (!rhs) {
		return -1;
	}

	ret = (bt_compare_result_t)strncmp(lhs->name, rhs, len);

	if(ret == 0) {
		int lhs_len = (int)strlen(lhs->name);
		if(lhs_len > len) {
			ret = 1;
		}
		else if(lhs_len < len) {
			ret = -1;
		}
	}

	return ret;
}

nyoci_node_t
nyoci_node_init(
	nyoci_node_t self, nyoci_node_t node, const char* name
) {
	nyoci_node_t ret = NULL;

	require(self || (self = nyoci_node_alloc()), bail);

	ret = (nyoci_node_t)self;

	ret->request_handler = (void*)&nyoci_default_request_handler;

	if (node) {
		require(name, bail);
		ret->name = name;
#if NYOCI_NODE_ROUTER_USE_BTREE
		bt_insert(
			(void**)&((nyoci_node_t)node)->children,
			ret,
			(bt_compare_func_t)nyoci_node_compare,
			(bt_delete_func_t)nyoci_node_delete,
			NULL
		);
#else
		ll_prepend(
			(void**)&((nyoci_node_t)node)->children,
			(void*)ret
		);
#endif
		ret->parent = node;
	}

	DEBUG_PRINTF("%s: %p",__func__,ret);

bail:
	return ret;
}

void
nyoci_node_delete(nyoci_node_t node) {
	void** owner = NULL;

	DEBUG_PRINTF("%s: %p",__func__,node);

	if (node->parent) {
		owner = (void**)&((nyoci_node_t)node->parent)->children;
	}

	// Delete all child objects.
	while (((nyoci_node_t)node)->children) {
		nyoci_node_delete(((nyoci_node_t)node)->children);
	}

	if (owner) {
#if NYOCI_NODE_ROUTER_USE_BTREE
		bt_remove(owner,
			node,
			(bt_compare_func_t)nyoci_node_compare,
			(void*)node->finalize,
			NULL
		);
#else
		ll_remove(owner,(void*)node);
		if(node->finalize)
			node->finalize(node);
#endif
	}

bail:
	return;
}

nyoci_status_t
nyoci_node_get_path(
	nyoci_node_t node, char* path, coap_size_t max_path_len
) {
	nyoci_status_t ret = 0;

	require(node, bail);
	require(path, bail);

	if(node->parent) {
		// using recursion here just makes this code so much more pretty,
		// but it would be ideal to avoid using recursion at all,
		// to be nice to the stack. Just a topic of future investigation...
		ret = nyoci_node_get_path(node->parent, path, max_path_len);
	} else {
		path[0] = 0;
	}


	if(node->name) {
		size_t len;
		strlcat(path, "/", max_path_len);
		len = strlen(path);
		if(max_path_len>len)
			url_encode_cstr(path+len, node->name, max_path_len - len);
	}

bail:
	return ret;
}

nyoci_node_t
nyoci_node_find(
	nyoci_node_t node,
	const char* name,	// Unescaped.
	int name_len
) {
#if NYOCI_NODE_ROUTER_USE_BTREE
	return (nyoci_node_t)bt_find(
		(void*)&((nyoci_node_t)node)->children,
		name,
		(bt_compare_func_t)&nyoci_node_ncompare_cstr,
		(void*)(intptr_t)name_len
	);
#else
	// Ouch. Linear search.
	nyoci_node_t ret = node->children;
	while(ret && nyoci_node_ncompare_cstr(ret,name,name_len) != 0)
		ret = ll_next((void*)ret);
	return ret;
#endif
}

int
nyoci_node_find_next_with_path(
	nyoci_node_t node,
	const char* orig_path,	// Escaped.
	nyoci_node_t* next
) {
	const char* path = orig_path;

	require(next, bail);
	require(node, bail);
	require(path, bail);

	// Move past any preceding slashes.
	while(path[0] == '/')
		path++;

	if(path[0] == 0) {
		// Self.
		*next = node;
	} else {
		// Device or Variable.
		int namelen;
		for(namelen = 0; path[namelen]; namelen++) {
			if((path[namelen] == '/') || (path[namelen] == '?') ||
					(path[namelen] == '!'))
				break;
		}

		{
#if HAVE_C99_VLA
			// Warning: This could be dangerous!
			// We should evaluate the liklihood of blowing
			// the stack here.
			// SEC-TODO: Investigate potential for stack oveflow!
			char unescaped_name[namelen+1];
#else
			char *unescaped_name = malloc(namelen+1);
#endif
			size_t escaped_len = url_decode_str(
				unescaped_name,
				namelen+1,
				path,
				namelen
			);
			*next = nyoci_node_find(
				node,
				unescaped_name,
				(int)escaped_len
			);
#if !HAVE_C99_VLA // && !NYOCI_AVOID_MALLOC
			free(unescaped_name);
#endif
		}
		if(!*next) {
			DEBUG_PRINTF(
					"Unable to find node. node->name=%s, path=%s, namelen=%d",
				node->name, path, namelen);
			goto bail;
		}
	}

	if(!*next) {
		DEBUG_PRINTF(
				"Unable to find node. node->name=%s, path=%s", node->name,
			path);
		goto bail;
	}

	// Move to next name
	while(path[0] && (path[0] != '/') && (path[0] != '!') &&
			(path[0] != '?'))
		path++;

	// Move past any preceding slashes.
	while(path[0] == '/')
		path++;

bail:
	return (int)(path - orig_path);
}

nyoci_node_t
nyoci_node_find_with_path(
	nyoci_node_t node, const char* path
) {
	nyoci_node_t ret = NULL;

again:
	require(node, bail);
	require(path, bail);

	do {
		const char* nextPath = path;
		nextPath += nyoci_node_find_next_with_path(node, path, &ret);
		node = ret;
		DEBUG_PRINTF("%s: %p (nextPath = %s)", path, node, nextPath);
		path = nextPath;
	} while(ret && path[0]);

bail:
	return ret;
}

extern int nyoci_node_find_closest_with_path(
	nyoci_node_t node, const char* path, nyoci_node_t* closest
) {
	int ret = 0;

again:
	require(node, bail);
	require(path, bail);

	*closest = node;
	do {
		ret += nyoci_node_find_next_with_path(*closest, path + ret, &node);
		if(node)
			*closest = node;
	} while(node && path[ret]);

bail:
	return ret;
}

nyoci_node_t
nyoci_node_get_root(nyoci_node_t node) {
	if(node && node->parent)
		return nyoci_node_get_root(node->parent); // Recursion should be optimized away.
	return node;
}
