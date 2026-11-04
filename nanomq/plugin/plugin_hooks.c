//
// Copyright 2024 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
// The hook points in plugin.h only matter where the broker is allowed to
// refuse a client. CONNECT is decided inside the protocol stack, which must
// not call back into nanomq, so the stack keeps one function pointer and this
// file installs the dispatcher on it, once, before any listener exists. Publish
// and subscribe authorisation happens here, in the packet handlers.
#include "include/plugin.h"
#include "nng/protocol/mqtt/connect_hook.h"
#include "nng/protocol/mqtt/mqtt_parser.h"

static bool
nano_plugin_connect_auth(nano_connect_params *params)
{
	struct nano_hook_basic_auth event;

	event.clientid    = params->clientid;
	event.username    = params->username;
	event.password    = params->password;
	event.ip_addr     = params->ip_addr;
	event.proto_name  = params->proto_name;
	event.proto_ver   = params->proto_ver;
	event.clean_start = params->clean_start;

	return plugin_hook_call(HOOK_BASIC_AUTH, &event) == 0;
}

void
nano_plugin_hooks_install(void)
{
	// The seam below takes CONNECT authentication away from the broker's own
	// verify_connect(), and plugin_hook_call() answers 0 - "accepted" - when
	// nobody owns the point. So installing it unconditionally would let a
	// broker with no plugin, or with only plugins that claim other points,
	// accept every CONNECT and ignore allow_anonymous, the empty-credential
	// refusal and auth.password. Ask who owns it first; nanomq reload never
	// registers a plugin, so this answer holds for the life of the process.
	if (plugin_hook_has(HOOK_BASIC_AUTH)) {
		nano_connect_auth_set(nano_plugin_connect_auth);
		log_info("plugin: a plugin owns CONNECT authentication, "
		         "the built-in username/password check is not used");
		return;
	}
	log_info("plugin: no plugin owns CONNECT authentication, "
	         "the built-in username/password check stays in charge");
}

int
nano_plugin_acl_check(conn_param *cparam, conf *config, int action, const char *topic)
{
	struct nano_hook_acl_check event;

	// Birth, kill and other $SYS event messages are not something the client
	// published, so no plugin gets to deny them.
	if (cparam == NULL || topic == NULL) {
		return NANO_HOOK_ALLOWED;
	}

	event.action   = action;
	event.clientid = conn_param_get_clientid(cparam);
	event.username = (const char *) conn_param_get_username(cparam);
	event.ip_addr  = conn_param_get_ip_addr_v4(cparam);
	event.topic    = topic;

	if (plugin_hook_call(HOOK_ACL_CHECK, &event) == 0) {
		return NANO_HOOK_ALLOWED;
	}

	log_warn("plugin acl deny %s clientid [%s] username [%s] topic [%s]",
	    action == NANO_HOOK_ACL_PUB ? "publish" : "subscribe",
	    event.clientid != NULL ? event.clientid : "",
	    event.username != NULL ? event.username : "", topic);

	// auth.deny_action was written for the native ACL, but a plugin denial is
	// the same decision from the operator's point of view. Without ACL support
	// compiled in the option does not exist, so the packet is only dropped.
#if defined(ACL_SUPP)
	if (config != NULL && config->acl_deny_action == ACL_DISCONNECT) {
		return NANO_HOOK_DISCONNECT;
	}
#else
	(void) config;
#endif
	return NANO_HOOK_DENIED;
}
