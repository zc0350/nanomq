/*
 * cong-nanomq: JSONL login and ACL policy for NanoMQ, as an in-process plugin.
 *
 * The rules engine is the same code the Mosquitto plugin builds with:
 * cong_util.c, cong_digest.c, cong_auth.c, cong_acl.c and cong_topic.c live in
 * src/core as a copy (see VENDOR.md), so one rule file means the same thing on
 * both brokers as long as those copies match. Only the layer below differs: it
 * maps NanoMQ's hook points onto the same core calls the mosquitto plugin makes.
 *
 * NanoMQ hands a plugin no configuration, so the two rule files come from the
 * environment:
 *
 *   CONG_AUTH_FILE   (default CONG_DEFAULT_AUTH_FILE)
 *   CONG_ACL_FILE    (default CONG_DEFAULT_ACL_FILE)
 *   CONG_DEBUG       set to anything to also log the decisions that allowed
 *
 * Build it against a patched NanoMQ tree; see README.md and the Makefile.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pthread.h>

#include "cong_core.h"

#include "include/plugin.h"

#define PLUGIN_NAME "cong-auth-acl"
#define PLUGIN_VERSION "1.1.1"

#define CONG_DEFAULT_AUTH_FILE "/etc/nanomq/cong_auth.jsonl"
#define CONG_DEFAULT_ACL_FILE "/etc/nanomq/cong_acl.jsonl"

struct cong_nanomq {
	char *auth_path;
	char *acl_path;
	struct cong_auth_table *auth;
	struct cong_acl_table *acl;
	pthread_rwlock_t lock;
};

static struct cong_nanomq *plugin = NULL;
static bool log_verbose = false;

/* ------------------------------------------------------------------ logging */

/* NanoMQ's log_* macros write through the broker's own logger, which a plugin
 * has no business touching before the log config is settled, so decisions go
 * to stderr - the same stream the broker writes to when it logs to console, so
 * the lines stay together in the journal. */
static void plugin_logger(int level, const char *fmt, va_list args)
{
	char        line[4096];
	const char *who;
	size_t      room;
	int         len;
	int         body;

	if(!log_verbose && (level == CONG_LOG_INFO || level == CONG_LOG_DEBUG)){
		return;
	}

	switch(level){
		case CONG_LOG_ERR:     who = "error"; break;
		case CONG_LOG_WARNING: who = "warn";  break;
		case CONG_LOG_NOTICE:  who = "notice"; break;
		case CONG_LOG_INFO:    who = "info";  break;
		default:               who = "debug"; break;
	}

	/* One write per line, newline included: every worker thread logs through
	 * here, and stdio only owns the stream for the duration of one call, so
	 * separate calls for the prefix, the body and the newline let another
	 * thread's line land in the middle of this one. */
	len = snprintf(line, sizeof(line), "[%s:%s] ", PLUGIN_NAME, who);
	if(len < 0 || (size_t) len >= sizeof(line)){
		return;
	}
	room = sizeof(line) - (size_t) len - 2;   /* room for the newline and the NUL */
	body = vsnprintf(line + len, room, fmt, args);
	if(body < 0){
		return;
	}
	len += body < (int) room ? body : (int) room - 1;
	line[len++] = '\n';
	line[len] = '\0';
	fwrite(line, 1, (size_t) len, stderr);
}

/* ------------------------------------------------------------ topic matchers */

/* Both directions come from src/core/cong_topic.c, the same translation unit the
 * Mosquitto plugin builds, so a rule file means one thing on either broker and
 * the .so needs nothing from the host beyond plugin_hook_register().
 *
 * Deliberately stricter than NanoMQ's own topic_filter(): that function compares
 * level by level and never asks whether a published topic carries wildcards, so
 * "sensor/+" would accept a PUBLISH on "sensor/#". Here a wildcard in a publish
 * topic, or a +/# that does not own its whole level, is refused outright (the ACL
 * layer turns that into CONG_ERROR, i.e. deny) rather than matched. The "$"
 * hierarchy guard is core's too - check_ifwildcard() has no notion of the
 * reserved $SYS space, and on this broker "#" does reach "$SYS/anything".
 *
 * The subscribe direction is a coverage question, not a string comparison: a rule
 * only allows a subscription filter it covers entirely, so "sensor/+" does not
 * authorise "sensor/#". topic_filter() could not express that - it is the same
 * function for both directions, and NanoMQ's native acl file checks a
 * subscription filter against the rule with it. */

static const struct cong_topic_ops topic_ops = {
	cong_topic_matches_sub,
	cong_sub_matches_acl
};

/* ---------------------------------------------------------------- callbacks */

static int cb_basic_auth(void *data)
{
	struct nano_hook_basic_auth *ev = data;
	enum cong_decision decision;
	unsigned lineno = 0;
	int rc;

	/* The log lines below quote plugin->auth_path, so they stay inside the read
	 * lock: cb_reload() frees and replaces that string under the write lock. */
	pthread_rwlock_rdlock(&plugin->lock);
	decision = cong_auth_check(plugin->auth, ev->username, ev->clientid, ev->ip_addr,
			ev->password, ev->password ? strlen(ev->password) : 0, &lineno);

	switch(decision){
		case CONG_ALLOW:
			cong_log(CONG_LOG_DEBUG, "login allowed for username=\"%s\" clientid=\"%s\" from %s (auth rule line %u)",
					ev->username ? ev->username : "", ev->clientid ? ev->clientid : "",
					ev->ip_addr ? ev->ip_addr : "unknown", lineno);
			rc = 0;
			break;
		case CONG_DENY:
			cong_log(CONG_LOG_WARNING, "login refused: username=\"%s\" clientid=\"%s\" from %s matched a rule but the password digest does not",
					ev->username ? ev->username : "", ev->clientid ? ev->clientid : "",
					ev->ip_addr ? ev->ip_addr : "unknown");
			rc = 1;
			break;
		case CONG_NO_MATCH:
			cong_log(CONG_LOG_WARNING, "login refused: username=\"%s\" clientid=\"%s\" from %s matches no rule in %s",
					ev->username ? ev->username : "", ev->clientid ? ev->clientid : "",
					ev->ip_addr ? ev->ip_addr : "unknown", plugin->auth_path);
			rc = 1;
			break;
		case CONG_ERROR:
		default:
			cong_log(CONG_LOG_ERR, "login refused after an internal error for username=\"%s\"",
					ev->username ? ev->username : "");
			rc = 1;
			break;
	}
	pthread_rwlock_unlock(&plugin->lock);
	return rc;
}

static int cb_acl_check(void *data)
{
	struct nano_hook_acl_check *ev = data;
	enum cong_decision decision;
	int access;
	unsigned lineno = 0;

	access = (ev->action == NANO_HOOK_ACL_SUB) ? CONG_ACL_SUBSCRIBE : CONG_ACL_WRITE;

	pthread_rwlock_rdlock(&plugin->lock);
	decision = cong_acl_check(plugin->acl, &topic_ops, access, ev->topic,
			ev->username, ev->clientid, ev->ip_addr, &lineno);

	switch(decision){
		case CONG_ALLOW:
			cong_log(CONG_LOG_DEBUG, "acl allowed action=%d topic=\"%s\" clientid=\"%s\" (acl rule line %u)",
					ev->action, ev->topic, ev->clientid ? ev->clientid : "", lineno);
			pthread_rwlock_unlock(&plugin->lock);
			return 0;
		case CONG_DENY:
			cong_log(CONG_LOG_WARNING, "acl denied action=%d topic=\"%s\" username=\"%s\" clientid=\"%s\" (acl rule line %u)",
					ev->action, ev->topic, ev->username ? ev->username : "",
					ev->clientid ? ev->clientid : "", lineno);
			break;
		case CONG_NO_MATCH:
			cong_log(CONG_LOG_WARNING, "acl denied action=%d topic=\"%s\" username=\"%s\" clientid=\"%s\": no rule in %s applies",
					ev->action, ev->topic, ev->username ? ev->username : "",
					ev->clientid ? ev->clientid : "", plugin->acl_path);
			break;
		case CONG_ERROR:
		default:
			cong_log(CONG_LOG_ERR, "acl denied action=%d topic=\"%s\" after an internal error",
					ev->action, ev->topic);
			break;
	}
	pthread_rwlock_unlock(&plugin->lock);
	return 1;
}

/* ------------------------------------------------------------------- reload */

static bool reload_tables(void)
{
	struct cong_auth_table *new_auth;
	struct cong_acl_table *new_acl;

	pthread_rwlock_wrlock(&plugin->lock);

	/* Load both new tables before dropping either old one. A rules file that no
	 * longer parses keeps the broker running on the last valid policy: a typo
	 * during a fleet update must not take the broker down, and must not widen
	 * access either. The error below is the signal to fix the file. */
	new_auth = cong_auth_load(plugin->auth_path);
	if(!new_auth){
		cong_log(CONG_LOG_ERR, "reload FAILED for %s: still enforcing the previously loaded rules, nothing was reloaded",
				plugin->auth_path);
		pthread_rwlock_unlock(&plugin->lock);
		return false;
	}
	new_acl = cong_acl_load(plugin->acl_path);
	if(!new_acl){
		cong_auth_free(new_auth);
		cong_log(CONG_LOG_ERR, "reload FAILED for %s: still enforcing the previously loaded rules, nothing was reloaded",
				plugin->acl_path);
		pthread_rwlock_unlock(&plugin->lock);
		return false;
	}

	cong_auth_free(plugin->auth);
	cong_acl_free(plugin->acl);
	plugin->auth = new_auth;
	plugin->acl = new_acl;

	pthread_rwlock_unlock(&plugin->lock);
	return true;
}

static int cb_reload(void *data)
{
	(void) data;
	/* The broker answers "reload succeed!" without asking us, so the return
	 * value carries no decision; the log line above is what an operator sees. */
	reload_tables();
	return 0;
}

/* --------------------------------------------------------------- plugin api */

static char *config_path(const char *env, const char *fallback)
{
	const char *value = getenv(env);

	if(value == NULL || value[0] == '\0'){
		value = fallback;
	}
	return strdup(value);
}

int nano_plugin_init(void)
{
	struct cong_nanomq *new_plugin;

	cong_set_logger(plugin_logger);
	log_verbose = getenv("CONG_DEBUG") != NULL;

	new_plugin = calloc(1, sizeof(struct cong_nanomq));
	if(!new_plugin){
		cong_log(CONG_LOG_ERR, "out of memory");
		return -1;
	}
	if(pthread_rwlock_init(&new_plugin->lock, NULL) != 0){
		cong_log(CONG_LOG_ERR, "cannot create the rules lock");
		free(new_plugin);
		return -1;
	}
	new_plugin->auth_path = config_path("CONG_AUTH_FILE", CONG_DEFAULT_AUTH_FILE);
	new_plugin->acl_path = config_path("CONG_ACL_FILE", CONG_DEFAULT_ACL_FILE);
	if(!new_plugin->auth_path || !new_plugin->acl_path){
		cong_log(CONG_LOG_ERR, "out of memory");
		free(new_plugin->auth_path);
		free(new_plugin->acl_path);
		pthread_rwlock_destroy(&new_plugin->lock);
		free(new_plugin);
		return -1;
	}

	/* From here on the structure stays alive, because the callbacks below may
	 * already have been registered and they read it. Registering the hooks before
	 * loading the rules is what makes a failure to load fail closed: the tables
	 * stay NULL, and both engines refuse everything when they are. */
	plugin = new_plugin;

	if(plugin_hook_register(HOOK_BASIC_AUTH, cb_basic_auth) != 0 ||
			plugin_hook_register(HOOK_ACL_CHECK, cb_acl_check) != 0 ||
			plugin_hook_register(HOOK_RELOAD, cb_reload) != 0){
		cong_log(CONG_LOG_ERR, "cannot register the login, acl or reload hook");
		return -1;
	}

	/* Rules that cannot be read are a fatal start-up error, not a reason to run
	 * without a policy - the patched broker stops when this returns non zero. */
	plugin->auth = cong_auth_load(plugin->auth_path);
	if(!plugin->auth){
		cong_log(CONG_LOG_ERR, "cannot load %s", plugin->auth_path);
		return -1;
	}
	plugin->acl = cong_acl_load(plugin->acl_path);
	if(!plugin->acl){
		cong_log(CONG_LOG_ERR, "cannot load %s", plugin->acl_path);
		return -1;
	}

	cong_log(CONG_LOG_NOTICE, "%s %s enforcing %s and %s", PLUGIN_NAME, PLUGIN_VERSION,
			plugin->auth_path, plugin->acl_path);
	return 0;
}
