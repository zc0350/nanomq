//
// Copyright 2024 NanoMQ Team, Inc. <jaylin@emqx.io>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//
#ifndef NANOMQ_PLUGIN_H
#define NANOMQ_PLUGIN_H

#include <stdbool.h>
#include <stdint.h>

#include "nng/nng.h"
#include "nng/supplemental/nanolib/conf.h"
#include "nng/supplemental/nanolib/log.h"

struct nano_plugin {
	char *path;
	int (*init)(void);
};

enum hook_point {
	HOOK_USER_PROPERTY,
	// CONNECT authentication. Data: struct nano_hook_basic_auth *.
	// The callback returns 0 to accept the client and non zero to refuse
	// it. Once a plugin owns this point it replaces the built-in username
	// and password check, so a refusal is final.
	HOOK_BASIC_AUTH,
	// Publish and subscribe authorisation. Data: struct nano_hook_acl_check *.
	// The callback returns 0 to allow and non zero to deny; the broker then
	// applies the configured auth.deny_action, exactly as for its own ACL.
	HOOK_ACL_CHECK,
	// Sent after "nanomq reload" has swapped the broker's own tables, so a
	// plugin can re-read the files it owns. Data: NULL. The return value is
	// ignored; a plugin that cannot reload keeps the rules it already has.
	HOOK_RELOAD,
};

// Everything a plugin needs to decide a CONNECT. The strings belong to the
// protocol stack and are only valid while the callback runs.
struct nano_hook_basic_auth {
	const char *clientid;
	const char *username; // NULL when the client sent no username
	const char *password; // NULL when the client sent no password
	const char *ip_addr;
	const char *proto_name;
	uint8_t     proto_ver;
	bool        clean_start;
};

// What a plugin is asked to authorise. action is one of the values below;
// topic is never NULL and never an internal event message.
#define NANO_HOOK_ACL_PUB 1
#define NANO_HOOK_ACL_SUB 2

struct nano_hook_acl_check {
	int         action;
	const char *clientid;
	const char *username;
	const char *ip_addr;
	const char *topic;
};

// What nano_plugin_acl_check() returns.
#define NANO_HOOK_ALLOWED 0
#define NANO_HOOK_DENIED 1
#define NANO_HOOK_DISCONNECT 2

struct plugin_hook {
	unsigned int point;
	int (*cb)(void *data);
};

extern int plugin_hook_register(unsigned int point, int (*cb)(void *data));
extern int plugin_hook_call(unsigned int point, void *data);
// Whether any plugin owns this point. plugin_hook_call() answers 0 both when a
// plugin allowed the action and when no plugin was asked at all, so a caller
// that has to tell those apart - the CONNECT seam does - asks here.
extern bool plugin_hook_has(unsigned int point);
extern int plugin_register(char *path);
extern void plugins_clear();
extern int plugin_init(struct nano_plugin *plugin);

// Called once at startup, after every plugin has been registered and before any
// listener exists: it hands the CONNECT decision to the plugin only when some
// plugin really owns HOOK_BASIC_AUTH, because that seam replaces the broker's
// built-in username/password check rather than adding to it. With no plugin
// configured, or only plugins that claim other points, the built-in check stays
// in charge and nothing about the broker's behaviour changes.
extern void nano_plugin_hooks_install(void);

// Asks the HOOK_ACL_CHECK owner about one publish or subscription. Returns
// NANO_HOOK_ALLOWED when no plugin owns the point or the plugin allows it;
// otherwise the deny action taken from the broker configuration, so that
// auth.deny_action keeps working for plugins as well as for native ACL rules.
// Logging the refusal is this function's job, not the caller's.
extern int nano_plugin_acl_check(
    conn_param *cparam, conf *config, int action, const char *topic);

#endif // NANOMQ_PLUGIN_H
