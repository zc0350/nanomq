#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cong_core.h"

static const char *const auth_keys[] = {
	"username", "match",
	"clientid", "clientid_match",
	"ip",
	"salt", "alg", "scheme",
	"sanitize",
	NULL
};

struct auth_load {
	struct cong_auth_rule *head;
	struct cong_auth_rule *tail;
	size_t rule_count;
	size_t regex_count;
};

/* A segment that opens with a factor name but is not that name is nearly always
 * a scheme written as one word: "salt_x" reads as the literal text "salt_x", not
 * as salt followed by an underscore, and neither does "usernamee" mean username.
 * Requiring a separator after the name would only cover the first of those two,
 * and a PART_TEXT segment is by definition not the keyword itself, so the prefix
 * is the whole test. The login still fails closed, so this is a warning and not
 * an error - the operator is the only one who can tell which of the two they
 * meant. Returns the factor name, or NULL. */
static const char *scheme_text_factor_typo(const char *text)
{
	static const char *const names[] = {"username", "clientid", "salt"};
	unsigned i;

	for(i = 0; i < sizeof(names) / sizeof(names[0]); i++){
		if(!strncmp(text, names[i], strlen(names[i]))){
			return names[i];
		}
	}
	return NULL;
}

static bool auth_rule_cb(cJSON *record, unsigned lineno, const char *path, void *userdata)
{
	struct auth_load *load = userdata;
	struct cong_auth_rule *rule;
	struct cong_scheme_use use;
	const cJSON *item;
	const char *text;
	const char *typo;
	unsigned i;

	if(!cong_json_check_keys(record, auth_keys, "an auth rule", path, lineno)){
		return false;
	}

	rule = calloc(1, sizeof(struct cong_auth_rule));
	if(!rule){
		cong_log(CONG_LOG_ERR, "%s:%u: out of memory", path, lineno);
		return false;
	}
	rule->lineno = lineno;
	rule->sanitize = true;

	/* The scheme comes first because it decides whether the two patterns below
	 * have to be compiled with captures - and, like the ACL loader, only the ones
	 * that reference a group pay for them. */
	item = cJSON_GetObjectItemCaseSensitive(record, "scheme");
	if(!item){
		cong_log(CONG_LOG_ERR, "%s:%u: an auth rule needs \"scheme\"", path, lineno);
		goto fail_scheme;
	}
	text = cong_json_string(item);
	if(!text){
		cong_log(CONG_LOG_ERR, "%s:%u: \"scheme\" must be a string", path, lineno);
		goto fail_scheme;
	}
	if(!cong_scheme_parse(text, &rule->scheme)){
		cong_log(CONG_LOG_ERR, "%s:%u: \"scheme\" must be a \"+\"-joined list of username, clientid and salt, or of templates over their capture groups (%%u1..%%u9, %%c1..%%c9, with %% for a literal percent), any order, up to %d segments, got \"%s\"",
				path, lineno, CONG_SCHEME_MAX_PARTS, text);
		goto fail_scheme;
	}
	cong_scheme_usage(&rule->scheme, &use);
	for(i = 0; i < rule->scheme.count; i++){
		if(rule->scheme.items[i].part != PART_TEXT){
			continue;
		}
		if(rule->scheme.items[i].username_group == 0
				&& rule->scheme.items[i].clientid_group == 0){
			typo = scheme_text_factor_typo(rule->scheme.items[i].text);
			if(typo){
				cong_log(CONG_LOG_WARNING, "%s:%u: \"scheme\" segment \"%s\" is literal text, not the factor it starts with; if you meant \"%s\" plus the rest, write two segments (\"%s+%s\")",
						path, lineno, rule->scheme.items[i].text, typo, typo,
						rule->scheme.items[i].text + strlen(typo));
			}
		}
	}

	if(!cong_subject_from_json(record, "username", "match", &rule->user,
			use.username_groups > 0, path, lineno)){
		goto fail_subjects;
	}
	if(!cong_subject_from_json(record, "clientid", "clientid_match", &rule->clientid,
			use.clientid_groups > 0, path, lineno)){
		goto fail_subjects;
	}
	if(rule->user.kind == CONG_MATCH_REGEX || rule->clientid.kind == CONG_MATCH_REGEX){
		load->regex_count++;
	}
	/* A %uN reference is a promise about the username pattern, and a promise the
	 * file does not keep is a password no device can compute, so it stops the
	 * whole load rather than quietly digesting an empty group. */
	if(use.username_groups > 0 && rule->user.ngroups < use.username_groups){
		cong_log(CONG_LOG_ERR, "%s:%u: \"scheme\" references group %%u%d of the username, but \"username\" has %d capture group(s)",
				path, lineno, use.username_groups, rule->user.ngroups);
		goto fail_subjects;
	}
	if(use.clientid_groups > 0 && rule->clientid.ngroups < use.clientid_groups){
		cong_log(CONG_LOG_ERR, "%s:%u: \"scheme\" references group %%c%d of the clientid, but \"clientid\" has %d capture group(s)",
				path, lineno, use.clientid_groups, rule->clientid.ngroups);
		goto fail_subjects;
	}
	if(!use.salt){
		cong_log(CONG_LOG_WARNING, "%s:%u: \"scheme\" never names salt, so the \"salt\" of this rule is dead config",
				path, lineno);
	}
	/* scheme "salt" alone (or a repeat of one identity) makes the password a
	 * constant every client of this rule shares, so nothing but the constraints
	 * below it protects the account. Legal, but rarely what was meant. */
	if(!use.username && !use.clientid){
		cong_log(CONG_LOG_WARNING, "%s:%u: \"scheme\" names neither username nor clientid, so every client of this rule shares one password",
				path, lineno);
	}

	item = cJSON_GetObjectItemCaseSensitive(record, "ip");
	if(item){
		text = cong_json_string(item);
		if(!text){
			cong_log(CONG_LOG_ERR, "%s:%u: \"ip\" must be a string", path, lineno);
			goto fail_subjects;
		}
		if(!cong_net_parse(&rule->ip, text, "ip", path, lineno)){
			goto fail_subjects;
		}
		rule->has_ip = true;
	}

	item = cJSON_GetObjectItemCaseSensitive(record, "salt");
	if(!item){
		cong_log(CONG_LOG_ERR, "%s:%u: an auth rule needs \"salt\"", path, lineno);
		goto fail_subjects;
	}
	text = cong_json_string(item);
	if(!text){
		cong_log(CONG_LOG_ERR, "%s:%u: \"salt\" must be a string", path, lineno);
		goto fail_subjects;
	}
	rule->salt = strdup(text);
	if(!rule->salt){
		cong_log(CONG_LOG_ERR, "%s:%u: out of memory", path, lineno);
		goto fail_subjects;
	}
	rule->salt_len = strlen(text);

	item = cJSON_GetObjectItemCaseSensitive(record, "alg");
	if(!item){
		cong_log(CONG_LOG_ERR, "%s:%u: an auth rule needs \"alg\"", path, lineno);
		goto fail_subjects;
	}
	text = cong_json_string(item);
	if(!text){
		cong_log(CONG_LOG_ERR, "%s:%u: \"alg\" must be a string", path, lineno);
		goto fail_subjects;
	}
	if(!cong_alg_parse(text, &rule->alg)){
		cong_log(CONG_LOG_ERR, "%s:%u: \"alg\" must be md5, sha1, sha256 or sha512, got \"%s\"",
				path, lineno, text);
		goto fail_subjects;
	}

	item = cJSON_GetObjectItemCaseSensitive(record, "sanitize");
	if(item && !cong_json_bool(item, &rule->sanitize)){
		cong_log(CONG_LOG_ERR, "%s:%u: \"sanitize\" must be true or false", path, lineno);
		goto fail_subjects;
	}

	if(load->tail){
		load->tail->next = rule;
	}else{
		load->head = rule;
	}
	load->tail = rule;
	load->rule_count++;
	return true;

fail_subjects:
	free(rule->salt);
	cong_subject_free(&rule->clientid);
	cong_subject_free(&rule->user);
fail_scheme:
	cong_scheme_free(&rule->scheme);
	free(rule);
	return false;
}

struct cong_auth_table *cong_auth_load(const char *path)
{
	struct auth_load load = {NULL, NULL, 0, 0};
	struct cong_auth_table *table;

	if(!cong_jsonl_parse(path, auth_rule_cb, &load)){
		cong_auth_free_from_rules(load.head);
		return NULL;
	}

	table = calloc(1, sizeof(struct cong_auth_table));
	if(!table){
		cong_log(CONG_LOG_ERR, "out of memory");
		cong_auth_free_from_rules(load.head);
		return NULL;
	}
	table->rules = load.head;
	table->rule_count = load.rule_count;
	table->regex_count = load.regex_count;

	if(table->rule_count == 0){
		cong_log(CONG_LOG_WARNING, "%s contains no auth rules, so every login will be refused", path);
	}else{
		cong_log(CONG_LOG_INFO, "%s: %zu auth rule(s), %zu of them use a regular expression",
				path, table->rule_count, table->regex_count);
	}
	return table;
}

void cong_auth_free_from_rules(struct cong_auth_rule *rule)
{
	struct cong_auth_rule *next;

	while(rule){
		next = rule->next;
		cong_scheme_free(&rule->scheme);
		cong_subject_free(&rule->clientid);
		cong_subject_free(&rule->user);
		free(rule->salt);
		free(rule);
		rule = next;
	}
}

void cong_auth_free(struct cong_auth_table *table)
{
	if(!table){
		return;
	}
	cong_auth_free_from_rules(table->rules);
	free(table);
}

/* An identity the client did not send is not the same thing as an identity that
 * cleans to the empty string: the first is nothing to verify against, the second
 * is a name the device really has. Presence is therefore judged on the raw text. */
static bool auth_factor_present(const char *text)
{
	return text != NULL && text[0] != '\0';
}

/* 0 = usable (out points at raw or at *owned), 1 = the client sent nothing,
 * -1 = out of memory. */
static int auth_identity(const struct cong_auth_rule *rule, const char *raw,
		char **owned, const char **out)
{
	size_t size;

	/* A scheme may name the same factor more than once ("username+salt+username"
	 * is legal), so a value prepared for an earlier segment is reused as is.
	 * Resetting the pointer here instead would drop the previous allocation. */
	if(*owned){
		*out = *owned;
		return 0;
	}
	if(!auth_factor_present(raw)){
		return 1;
	}
	if(!rule->sanitize){
		*out = raw;
		return 0;
	}
	size = strlen(raw) + 1;
	*owned = malloc(size);
	if(!*owned){
		cong_log(CONG_LOG_ERR, "out of memory while checking a login");
		return -1;
	}
	if(cong_sanitize_identity(raw, *owned, size) == (size_t) -1){
		free(*owned);
		*owned = NULL;
		return -1;
	}
	*out = *owned;
	return 0;
}

static bool auth_rule_verifies(const struct cong_auth_rule *rule, const char *username,
		const char *clientid, const char *password, size_t password_len)
{
	uint8_t expected[64];
	uint8_t supplied[64];
	size_t expected_len = 0;
	size_t supplied_len = 0;
	/* Zeroed so that a segment added to enum cong_scheme_part without a case
	 * below digests as nothing instead of reading an uninitialised pointer. */
	struct cong_digest_part parts[CONG_SCHEME_MAX_PARTS] = {{NULL, 0}};
	char *owned[CONG_SCHEME_MAX_PARTS] = {NULL};
	char *user_owned = NULL;
	char *client_owned = NULL;
	struct cong_groups user_groups, client_groups;
	bool user_groups_read = false;
	bool client_groups_read = false;
	bool matched = false;
	unsigned i;

	if(cong_hex_decode(password, password_len, supplied, sizeof(supplied), &supplied_len) != 0){
		/* The password is not a hex digest at all. */
		return false;
	}

	/* Every identity the scheme names must be on the wire. Digesting an absent
	 * one as the empty string would let a client that sends no clientid
	 * authenticate against whatever digest the operator computed for "". */
	for(i = 0; i < rule->scheme.count; i++){
		const struct cong_scheme_item *item = &rule->scheme.items[i];

		switch(item->part){
			case PART_USERNAME: {
				const char *whole;

				if(auth_identity(rule, username, &user_owned, &whole) != 0){
					goto cleanup;
				}
				parts[i].data = (const uint8_t *) whole;
				parts[i].len = strlen(whole);
				break;
			}
			case PART_CLIENTID: {
				const char *whole;

				if(auth_identity(rule, clientid, &client_owned, &whole) != 0){
					goto cleanup;
				}
				parts[i].data = (const uint8_t *) whole;
				parts[i].len = strlen(whole);
				break;
			}
			case PART_SALT:
				parts[i].data = (const uint8_t *) rule->salt;
				parts[i].len = rule->salt_len;
				break;
			case PART_TEXT: {
				const struct cong_groups *user_from = NULL;
				const struct cong_groups *client_from = NULL;

				if(item->uses_username){
					if(!auth_factor_present(username)){
						goto cleanup;
					}
					if(item->username_group > 0){
						if(!user_groups_read){
							/* cong_subject_match_groups() always records whether it
							 * filled the table, and the loader has already promised this
							 * pattern was compiled with enough groups. A group that did
							 * not take part in the match contributes nothing. */
							cong_subject_match_groups(&rule->user, username, &user_groups);
							user_groups_read = true;
						}
						user_from = &user_groups;
					}
				}
				if(item->uses_clientid){
					if(!auth_factor_present(clientid)){
						goto cleanup;
					}
					if(item->clientid_group > 0){
						if(!client_groups_read){
							cong_subject_match_groups(&rule->clientid, clientid, &client_groups);
							client_groups_read = true;
						}
						client_from = &client_groups;
					}
				}
				if(!cong_scheme_text_build(item, rule->sanitize, user_from, client_from,
						&owned[i], &parts[i].len)){
					goto cleanup;
				}
				parts[i].data = (const uint8_t *) owned[i];
				break;
			}
		}
	}
	if(cong_digest_parts(rule->alg, expected, sizeof(expected), &expected_len,
			parts, rule->scheme.count) != 0){
		goto cleanup;
	}
	if(supplied_len == expected_len && cong_secret_cmp(expected, supplied, expected_len) == 0){
		matched = true;
	}

cleanup:
	for(i = 0; i < CONG_SCHEME_MAX_PARTS; i++){
		free(owned[i]);
	}
	free(user_owned);
	free(client_owned);
	return matched;
}

enum cong_decision cong_auth_check(const struct cong_auth_table *table,
		const char *username, const char *clientid, const char *client_ip,
		const char *password, size_t password_len, unsigned *matched_lineno)
{
	const struct cong_auth_rule *rule;
	unsigned candidates = 0;
	int pass;

	if(matched_lineno){
		*matched_lineno = 0;
	}
	if(!table || table->rule_count == 0){
		return CONG_NO_MATCH;
	}
	if(!password || password_len == 0){
		/* Nothing to verify against, and a rule cannot recover a secret by
		 * guessing: refuse before touching any rule. */
		return CONG_NO_MATCH;
	}

	/* Pass 0 considers rules that name the username exactly, pass 1 the ones
	 * using a regular expression or "*". Exact rules win even when a regex rule
	 * appears earlier in the file, so a specific account can be overridden
	 * without hunting down every pattern above it. Within a pass the file order
	 * is kept. */
	for(pass = 0; pass < 2; pass++){
		for(rule = table->rules; rule; rule = rule->next){
			bool exact = (rule->user.kind == CONG_MATCH_EXACT);

			if(pass == 0 ? !exact : exact){
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
			candidates++;
			if(auth_rule_verifies(rule, username, clientid, password, password_len)){
				if(matched_lineno){
					*matched_lineno = rule->lineno;
				}
				return CONG_ALLOW;
			}
		}
	}

	return candidates > 0 ? CONG_DENY : CONG_NO_MATCH;
}
