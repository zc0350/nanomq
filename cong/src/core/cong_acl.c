#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cong_core.h"

static const char *const acl_keys[] = {
	"effect",
	"user", "match",
	"clientid", "clientid_match",
	"ip",
	"action",
	"topics",
	NULL
};

struct acl_load {
	struct cong_acl_rule *head;
	struct cong_acl_rule *tail;
	size_t rule_count;
};

static void acl_rule_free(struct cong_acl_rule *rule);

/* Whether this topic has to be expanded before matching, and whether the
 * expansion needs capture groups. Whether the rule lives in the $ hierarchy is
 * decided at check time, on the expanded pattern, because an expansion can make
 * the first byte a '$'. The token walk here is exactly the walk the expander
 * takes, so that "%%1" is a percent followed by a digit and not group one. */
static void topic_classify(struct cong_topic *topic)
{
	const char *p;
	int max_group = 0;

	topic->needs_expand = (strchr(topic->pattern, '%') != NULL);
	topic->needs_captures = false;
	topic->max_group = 0;

	p = topic->pattern;
	while(*p){
		if(*p != '%'){
			p++;
			continue;
		}
		if(p[1] == '%'){
			p += 2;
			continue;
		}
		if(p[1] >= '0' && p[1] <= '9'){
			/* %0 is the whole match and always exists, so it raises no demand on
			 * the group count, but the captures still have to be kept. */
			if(p[1] >= '1' && p[1] - '0' > max_group){
				max_group = p[1] - '0';
			}
			topic->needs_captures = true;
			p += 2;
			continue;
		}
		p += 1;
	}
	topic->max_group = max_group;
}

static struct cong_topic *topic_new(const char *pattern, enum cong_topic_kind kind)
{
	struct cong_topic *topic;

	topic = calloc(1, sizeof(struct cong_topic));
	if(!topic){
		return NULL;
	}
	topic->pattern = strdup(pattern);
	if(!topic->pattern){
		free(topic);
		return NULL;
	}
	topic->kind = kind;
	topic_classify(topic);
	return topic;
}

/* Whether any topic of this record references a capture, and the highest group
 * number it references. Returns false only on out of memory. */
static bool record_group_scan(const cJSON *record, bool *needs_captures, int *max_group)
{
	const cJSON *item, *child;
	struct cong_topic *probe;

	*needs_captures = false;
	*max_group = 0;

	item = cJSON_GetObjectItemCaseSensitive(record, "topics");
	if(!item || !cJSON_IsArray(item)){
		return true;
	}
	for(child = item->child; child; child = child->next){
		const char *text = cong_json_string(child);
		if(!text && cJSON_IsObject(child)){
			const cJSON *eq = cJSON_GetObjectItemCaseSensitive(child, "eq");
			text = cong_json_string(eq);
		}
		if(!text){
			continue;
		}
		/* Classifying a throwaway copy is the cheapest way to run exactly the
		 * same token scan the loader will use. */
		probe = topic_new(text, CONG_TOPIC_WILDCARD);
		if(!probe){
			return false;
		}
		if(probe->needs_captures){
			*needs_captures = true;
		}
		if(probe->max_group > *max_group){
			*max_group = probe->max_group;
		}
		free(probe->pattern);
		free(probe);
	}
	return true;
}

static bool acl_rule_cb(cJSON *record, unsigned lineno, const char *path, void *userdata)
{
	struct acl_load *load = userdata;
	struct cong_acl_rule *rule;
	const cJSON *item, *child;
	const char *text;
	bool needs_captures;
	int want_group;

	if(!cong_json_check_keys(record, acl_keys, "an acl rule", path, lineno)){
		return false;
	}

	rule = calloc(1, sizeof(struct cong_acl_rule));
	if(!rule){
		cong_log(CONG_LOG_ERR, "%s:%u: out of memory", path, lineno);
		return false;
	}
	rule->lineno = lineno;

	item = cJSON_GetObjectItemCaseSensitive(record, "effect");
	text = item ? cong_json_string(item) : NULL;
	if(!text){
		cong_log(CONG_LOG_ERR, "%s:%u: an acl rule needs \"effect\" set to \"allow\" or \"deny\"", path, lineno);
		goto fail;
	}
	if(!strcmp(text, "allow")){
		rule->allow = true;
	}else if(!strcmp(text, "deny")){
		rule->allow = false;
	}else{
		cong_log(CONG_LOG_ERR, "%s:%u: \"effect\" must be \"allow\" or \"deny\", got \"%s\"", path, lineno, text);
		goto fail;
	}

	if(!cong_subject_from_json(record, "clientid", "clientid_match", &rule->clientid, false, path, lineno)){
		goto fail;
	}

	item = cJSON_GetObjectItemCaseSensitive(record, "ip");
	if(item){
		text = cong_json_string(item);
		if(!text){
			cong_log(CONG_LOG_ERR, "%s:%u: \"ip\" must be a string", path, lineno);
			goto fail;
		}
		if(!cong_net_parse(&rule->ip, text, "ip", path, lineno)){
			goto fail;
		}
		rule->has_ip = true;
	}

	rule->access_mask = CONG_ACL_ALL;
	item = cJSON_GetObjectItemCaseSensitive(record, "action");
	if(item){
		text = cong_json_string(item);
		if(!text){
			cong_log(CONG_LOG_ERR, "%s:%u: \"action\" must be a string", path, lineno);
			goto fail;
		}
		if(!strcmp(text, "publish")){
			rule->access_mask = CONG_ACL_WRITE;
		}else if(!strcmp(text, "subscribe")){
			rule->access_mask = CONG_ACL_READ | CONG_ACL_SUBSCRIBE | CONG_ACL_UNSUBSCRIBE;
		}else if(!strcmp(text, "all")){
			rule->access_mask = CONG_ACL_ALL;
		}else{
			cong_log(CONG_LOG_ERR, "%s:%u: \"action\" must be publish, subscribe or all, got \"%s\"",
					path, lineno, text);
			goto fail;
		}
	}

	/* \"user\" is compiled last because the topics decide whether its regular
	 * expression has to keep capture groups, and matching with captures is not
	 * free. */
	want_group = 0;
	if(!record_group_scan(record, &needs_captures, &want_group)){
		cong_log(CONG_LOG_ERR, "%s:%u: out of memory while scanning \"topics\"", path, lineno);
		goto fail;
	}
	if(!cong_subject_from_json(record, "user", "match", &rule->user, needs_captures, path, lineno)){
		goto fail;
	}
	if(needs_captures){
		if(rule->user.kind != CONG_MATCH_REGEX){
			cong_log(CONG_LOG_ERR, "%s:%u: \"topics\" references a %%0..%%9 group, but \"user\" is not a regular expression, so there is nothing to capture. Set \"match\": \"regex\" and wrap the part you want in brackets.",
					path, lineno);
			goto fail;
		}
		if(want_group > rule->user.ngroups){
			cong_log(CONG_LOG_ERR, "%s:%u: \"topics\" references %%%d, but the \"user\" expression (\"%s\") only has %d capture group(s)",
					path, lineno, want_group, rule->user.raw, rule->user.ngroups);
			goto fail;
		}
	}

	item = cJSON_GetObjectItemCaseSensitive(record, "topics");
	if(item){
		struct cong_topic **append = &rule->topics;
		struct cong_topic *topic;

		if(!cJSON_IsArray(item)){
			cong_log(CONG_LOG_ERR, "%s:%u: \"topics\" must be an array", path, lineno);
			goto fail;
		}
		for(child = item->child; child; child = child->next){
			text = cong_json_string(child);
			if(text){
				topic = topic_new(text, CONG_TOPIC_WILDCARD);
				if(!topic){
					cong_log(CONG_LOG_ERR, "%s:%u: out of memory", path, lineno);
					goto fail;
				}
				*append = topic;
				append = &topic->next;
				continue;
			}
			if(cJSON_IsObject(child)){
				/* child->next is the *next entry of the topics array*, not a sibling
				 * member of this object - the "only eq" promise has to be made about
				 * the object's own member list, or every {"eq": ...} that is not the
				 * last entry would look like it carried a second key. */
				const cJSON *members = child->child;
				const cJSON *eq = cJSON_GetObjectItemCaseSensitive(child, "eq");
				text = eq ? cong_json_string(eq) : NULL;
				if(!text){
					cong_log(CONG_LOG_ERR, "%s:%u: a \"topics\" entry object must be {\"eq\": \"<literal topic>\"} and nothing else",
							path, lineno);
					goto fail;
				}
				if(members->next){
					cong_log(CONG_LOG_ERR, "%s:%u: a \"topics\" entry object may only hold \"eq\"", path, lineno);
					goto fail;
				}
				topic = topic_new(text, CONG_TOPIC_EXACT);
				if(!topic){
					cong_log(CONG_LOG_ERR, "%s:%u: out of memory", path, lineno);
					goto fail;
				}
				*append = topic;
				append = &topic->next;
				continue;
			}
			cong_log(CONG_LOG_ERR, "%s:%u: a \"topics\" entry must be a string or an object", path, lineno);
			goto fail;
		}
		if(!rule->topics){
			cong_log(CONG_LOG_ERR, "%s:%u: \"topics\" is an empty array, which can never match. Drop the key to mean \"any topic\", or list at least one topic.",
					path, lineno);
			goto fail;
		}
	}

	if(load->tail){
		load->tail->next = rule;
	}else{
		load->head = rule;
	}
	load->tail = rule;
	load->rule_count++;
	return true;

fail:
	acl_rule_free(rule);
	return false;
}

static void acl_topic_free(struct cong_topic *topic)
{
	struct cong_topic *next;

	while(topic){
		next = topic->next;
		free(topic->pattern);
		free(topic);
		topic = next;
	}
}

static void acl_rule_free(struct cong_acl_rule *rule)
{
	if(!rule){
		return;
	}
	acl_topic_free(rule->topics);
	cong_subject_free(&rule->clientid);
	cong_subject_free(&rule->user);
	free(rule);
}

/* True when nothing at all restricts this rule: it names no client, no source
 * address and no topic, and it allows. Because evaluation stops at the first
 * hit, such a rule hands every client every topic and makes everything written
 * below it unreachable - which is exactly the shape a demo file ends with and a
 * production file must not. */
static bool unconditional_allow(const struct cong_acl_rule *rule)
{
	return rule->allow
		&& rule->user.kind == CONG_MATCH_ANY
		&& rule->clientid.kind == CONG_MATCH_ANY
		&& !rule->has_ip
		&& rule->topics == NULL;
}

struct cong_acl_table *cong_acl_load(const char *path)
{
	struct acl_load load = {NULL, NULL, 0};
	struct cong_acl_table *table;
	const struct cong_acl_rule *rule;

	if(!cong_jsonl_parse(path, acl_rule_cb, &load)){
		cong_acl_free_from_rules(load.head);
		return NULL;
	}

	table = calloc(1, sizeof(struct cong_acl_table));
	if(!table){
		cong_log(CONG_LOG_ERR, "out of memory");
		cong_acl_free_from_rules(load.head);
		return NULL;
	}
	table->rules = load.head;
	table->rule_count = load.rule_count;

	if(table->rule_count == 0){
		cong_log(CONG_LOG_WARNING, "%s contains no acl rules, so every publish and subscribe will be refused", path);
	}else{
		cong_log(CONG_LOG_INFO, "%s: %zu acl rule(s)", path, table->rule_count);
		for(rule = table->rules; rule; rule = rule->next){
			if(unconditional_allow(rule)){
				cong_log(CONG_LOG_NOTICE, "%s:%u allows every client on every topic, so every rule below this one is unreachable. Sample files ship with this line; a production file should end with a deny instead.",
						path, rule->lineno);
			}
		}
	}
	return table;
}

void cong_acl_free_from_rules(struct cong_acl_rule *rule)
{
	struct cong_acl_rule *next;

	while(rule){
		next = rule->next;
		acl_rule_free(rule);
		rule = next;
	}
}

void cong_acl_free(struct cong_acl_table *table)
{
	if(!table){
		return;
	}
	cong_acl_free_from_rules(table->rules);
	free(table);
}

/* Matches one topic entry of a matched rule against the topic in hand. The
 * caller has already applied the rule's subject and action constraints. */
enum entry_result {
	ENTRY_NO_MATCH,   /* this topic entry does not cover the topic */
	ENTRY_MATCHED,    /* it does, so the rule's own effect decides */
	ENTRY_ERROR       /* refuse the request, and say why */
};

static enum entry_result acl_topic_match(const struct cong_acl_rule *rule,
		const struct cong_topic *t, const struct cong_topic_ops *ops,
		bool checking_a_subscription, const char *topic, const char *username,
		const char *clientid, struct cong_groups *groups, bool *groups_filled)
{
	char expanded[CONG_EXPANDED_MAX];
	const char *pattern = t->pattern;
	enum cong_expand_result erc;
	bool result = false;
	int rc;

	if(t->needs_expand){
		if(t->needs_captures && !*groups_filled){
			if(!cong_subject_match_groups(&rule->user, username, groups)){
				cong_log(CONG_LOG_ERR, "acl rule line %u: the \"user\" expression no longer matches the username it was matched with",
						rule->lineno);
				return ENTRY_ERROR;
			}
			*groups_filled = true;
		}
		erc = cong_topic_expand(expanded, sizeof(expanded), pattern, clientid, username,
				t->needs_captures ? groups : NULL);
		if(erc == CONG_EXPAND_NO_MATCH){
			return ENTRY_NO_MATCH;
		}
		if(erc == CONG_EXPAND_WILDCARD){
			cong_log(CONG_LOG_ERR, "acl rule line %u: the identity used to expand the topic is refused because it contains + or #",
					rule->lineno);
			return ENTRY_ERROR;
		}
		if(erc != CONG_EXPAND_OK){
			cong_log(CONG_LOG_ERR, "acl rule line %u: expanding \"%s\" for this client failed (%d)",
					rule->lineno, pattern, (int) erc);
			return ENTRY_ERROR;
		}
		pattern = expanded;
	}

	if(t->kind == CONG_TOPIC_EXACT){
		return strcmp(pattern, topic) == 0 ? ENTRY_MATCHED : ENTRY_NO_MATCH;
	}

	/* A rule outside the $ hierarchy never covers a $ topic, so that "#" cannot
	 * be used to read "$SYS/#". Checked on the expanded pattern, because an
	 * expansion can change the first byte. */
	if(topic[0] == '$' && pattern[0] != '$'){
		return ENTRY_NO_MATCH;
	}

	if(checking_a_subscription){
		rc = ops->match_subscribe(pattern, topic, &result);
	}else{
		rc = ops->match_topic(pattern, topic, &result);
	}
	if(rc != 0){
		cong_log(CONG_LOG_ERR, "topic matching failed for acl rule line %u and topic \"%s\"",
				rule->lineno, topic);
		return ENTRY_ERROR;
	}
	return result ? ENTRY_MATCHED : ENTRY_NO_MATCH;
}

enum cong_decision cong_acl_check(const struct cong_acl_table *table,
		const struct cong_topic_ops *ops, int access, const char *topic,
		const char *username, const char *clientid, const char *client_ip,
		unsigned *matched_lineno)
{
	const struct cong_acl_rule *rule;
	const struct cong_topic *t;
	struct cong_groups groups;
	enum entry_result entry;
	bool checking_a_subscription;
	bool groups_filled;

	if(matched_lineno){
		*matched_lineno = 0;
	}
	if(!table || table->rule_count == 0){
		return CONG_NO_MATCH;
	}
	if(!topic || !ops){
		return CONG_ERROR;
	}

	checking_a_subscription = (access & (CONG_ACL_SUBSCRIBE | CONG_ACL_UNSUBSCRIBE)) != 0;

	/* File order decides: the first rule whose subject, action and topic all
	 * match wins, whether it allows or denies. This is the order of the acl.conf
	 * model rather than the mosquitto acl file model, where denials are silently
	 * hoisted above the allows of the same user. */
	for(rule = table->rules; rule; rule = rule->next){
		if(!(access & rule->access_mask)){
			continue;
		}
		if(!cong_subject_match(&rule->user, username)){
			continue;
		}
		if(!cong_subject_match(&rule->clientid, clientid)){
			continue;
		}
		if(rule->has_ip && !cong_net_match(&rule->ip, client_ip)){
			continue;
		}

		if(!rule->topics){
			if(matched_lineno){
				*matched_lineno = rule->lineno;
			}
			return rule->allow ? CONG_ALLOW : CONG_DENY;
		}

		groups.count = 0;
		groups_filled = false;
		for(t = rule->topics; t; t = t->next){
			entry = acl_topic_match(rule, t, ops, checking_a_subscription, topic,
					username, clientid, &groups, &groups_filled);
			if(entry == ENTRY_ERROR){
				return CONG_ERROR;
			}
			if(entry == ENTRY_MATCHED){
				if(matched_lineno){
					*matched_lineno = rule->lineno;
				}
				return rule->allow ? CONG_ALLOW : CONG_DENY;
			}
		}
	}

	return CONG_NO_MATCH;
}
