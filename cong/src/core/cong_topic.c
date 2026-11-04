#include "cong_core.h"

/*
 * MQTT wildcard matching, both directions.
 *
 * Ported from mosquitto 2.1.2 libcommon/topic_common.c: topic_matches_sub() and
 * sub_matches_acl() (EPL-2.0 OR BSD-3-Clause; this file takes the BSD-3-Clause
 * side, same as the plugin it serves). Two deliberate edits:
 *
 *  - The match_patterns branch is dropped. That branch interpolates the broker's
 *    own %c/%u into a pattern, and this layer templates identities itself in
 *    cong_topic_expand() before calling here, so by the time a pattern reaches
 *    these functions every % escape is already resolved and no '%' is special.
 *  - The error codes are this file's own. Behaviour, including which inputs are
 *    refused rather than merely unmatched, is unchanged; make diffcheck runs the
 *    two implementations against each other over a generated corpus.
 *
 * Why not call the broker's copies: 2.0.x has no mosquitto_sub_matches_acl() at
 * all, and its subscribe direction therefore falls back to the plain matcher,
 * which refuses any subscription filter carrying + or # (mosquitto_topic_matches_sub
 * ("sensor/#", "sensor/#") is MOSQ_ERR_INVAL, not a match). Matching here is what
 * makes one .so behave the same on 2.0.21 and 2.1.x instead of inheriting whichever
 * wildcard rules the host happens to ship.
 *
 * The two directions are genuinely different questions:
 *
 *   cong_topic_matches_sub(pattern, topic) - does the rule cover this published
 *       topic? The topic is concrete, so a + or # in it is a malformed publish and
 *       is refused.
 *   cong_sub_matches_acl(pattern, sub) - does the rule cover this *subscription
 *       filter*, which is itself a pattern? Covering means every topic the filter
 *       can select is allowed by the rule, so a broader filter is not matched by a
 *       narrower rule: "sensor/+" does not cover "sensor/#".
 */

/* Level-occupancy rules, identical in both directions: + and # each have to
 * occupy a whole level, and # has to be the last one. Violations are refusals,
 * not silent non-matches, so a typo in a rule file shows up as an error. */
static int whole_level_ok(const char *p, bool at_level_start)
{
	if(p[0] == '+'){
		if(!at_level_start && p[-1] != '/')
			return CONG_TOPIC_EINVAL;
		if(p[1] != '\0' && p[1] != '/')
			return CONG_TOPIC_EINVAL;
	}else if(p[0] == '#'){
		if(!at_level_start && p[-1] != '/')
			return CONG_TOPIC_EINVAL;
		if(p[1] != '\0')
			return CONG_TOPIC_EINVAL;
	}
	return CONG_TOPIC_OK;
}

/* Walk the rest of a pattern looking for a '#' that is not the final byte, so
 * that an input that cannot match anything is still reported as invalid rather
 * than as "no rule applied". */
static int tail_is_valid(const char *p)
{
	while(p[0] != '\0'){
		if(p[0] == '#' && p[1] != '\0')
			return CONG_TOPIC_EINVAL;
		p++;
	}
	return CONG_TOPIC_OK;
}

/* Walk a publish topic looking for wildcards. */
static int topic_has_no_wildcards(const char *topic)
{
	while(topic[0] != '\0'){
		if(topic[0] == '+' || topic[0] == '#')
			return CONG_TOPIC_EINVAL;
		topic++;
	}
	return CONG_TOPIC_OK;
}

int cong_topic_matches_sub(const char *pattern, const char *topic, bool *result)
{
	size_t spos;

	if(!result){
		return CONG_TOPIC_EINVAL;
	}
	*result = false;

	if(!pattern || !topic || pattern[0] == 0 || topic[0] == 0){
		return CONG_TOPIC_EINVAL;
	}

	/* The $ hierarchy is reserved to the broker: neither side may reach it with a
	 * pattern that does not start there itself. */
	if((pattern[0] == '$' && topic[0] != '$')
			|| (topic[0] == '$' && pattern[0] != '$')){

		return CONG_TOPIC_OK;
	}

	spos = 0;

	while(pattern[0] != 0){
		if(topic[0] == '+' || topic[0] == '#'){
			return CONG_TOPIC_EINVAL;
		}
		if(pattern[0] != topic[0] || topic[0] == 0){
			if(pattern[0] == '+'){
				if(whole_level_ok(pattern, spos == 0) != CONG_TOPIC_OK)
					return CONG_TOPIC_EINVAL;
				spos++;
				pattern++;
				while(topic[0] != 0 && topic[0] != '/'){
					if(topic[0] == '+' || topic[0] == '#'){
						return CONG_TOPIC_EINVAL;
					}
					topic++;
				}
				if(topic[0] == 0 && pattern[0] == 0){
					*result = true;
					return CONG_TOPIC_OK;
				}
			}else if(pattern[0] == '#'){
				if(whole_level_ok(pattern, spos == 0) != CONG_TOPIC_OK)
					return CONG_TOPIC_EINVAL;
				/* "#" consumes everything below, but the rest still has to be a
				 * legal publish topic. */
				if(topic_has_no_wildcards(topic) != CONG_TOPIC_OK)
					return CONG_TOPIC_EINVAL;
				*result = true;
				return CONG_TOPIC_OK;
			}else{
				/* "foo/+/#" covers "foo/bar": the trailing "#" may select the
				 * empty level that "+" consumed. */
				if(topic[0] == 0
						&& spos > 0
						&& pattern[-1] == '+'
						&& pattern[0] == '/'
						&& pattern[1] == '#'){
					*result = true;
					return CONG_TOPIC_OK;
				}
				if(tail_is_valid(pattern) != CONG_TOPIC_OK)
					return CONG_TOPIC_EINVAL;
				/* Valid input, but no match. */
				return CONG_TOPIC_OK;
			}
		}else{
			/* pattern[0] == topic[0] */
			if(topic[1] == 0){
				/* "foo/#" covers the single level "foo". */
				if(pattern[1] == '/'
						&& pattern[2] == '#'
						&& pattern[3] == 0){
					*result = true;
					return CONG_TOPIC_OK;
				}
			}
			spos++;
			pattern++;
			topic++;
			if(pattern[0] == 0 && topic[0] == 0){
				*result = true;
				return CONG_TOPIC_OK;
			}else if(topic[0] == 0 && pattern[0] == '+' && pattern[1] == 0){
				if(whole_level_ok(pattern, spos == 0) != CONG_TOPIC_OK)
					return CONG_TOPIC_EINVAL;
				*result = true;
				return CONG_TOPIC_OK;
			}
		}
	}
	/* Only the rule running out reaches here; *result is still false, and the
	 * leftover topic still has to be a legal one. */
	return topic_has_no_wildcards(topic);
}

int cong_sub_matches_acl(const char *pattern, const char *sub, bool *result)
{
	size_t apos;

	if(!result){
		return CONG_TOPIC_EINVAL;
	}
	*result = false;

	if(!pattern || !sub || pattern[0] == 0 || sub[0] == 0){
		return CONG_TOPIC_EINVAL;
	}

	if((pattern[0] == '$' && sub[0] != '$')
			|| (sub[0] == '$' && pattern[0] != '$')){

		return CONG_TOPIC_OK;
	}

	apos = 0;

	while(pattern[0] != 0){
		if(pattern[0] != sub[0] || sub[0] == 0){
			if(pattern[0] == '+'){
				if(sub[0] == '#'){
					/* "+" selects one level, "#" selects infinitely many, so this
					 * rule cannot cover that subscription. */
					return CONG_TOPIC_OK;
				}
				if(whole_level_ok(pattern, apos == 0) != CONG_TOPIC_OK)
					return CONG_TOPIC_EINVAL;
				apos++;
				pattern++;
				while(sub[0] != 0 && sub[0] != '/'){
					sub++;
				}
				if(sub[0] == 0 && pattern[0] == 0){
					*result = true;
					return CONG_TOPIC_OK;
				}
			}else if(pattern[0] == '#'){
				if(whole_level_ok(pattern, apos == 0) != CONG_TOPIC_OK)
					return CONG_TOPIC_EINVAL;
				/* "#" covers every filter below it, wildcard ones included. */
				*result = true;
				return CONG_TOPIC_OK;
			}else{
				if(sub[0] == 0
						&& apos > 0
						&& pattern[-1] == '+'
						&& pattern[0] == '/'
						&& pattern[1] == '#'){
					*result = true;
					return CONG_TOPIC_OK;
				}
				if(tail_is_valid(pattern) != CONG_TOPIC_OK)
					return CONG_TOPIC_EINVAL;
				/* Valid input, but no match. */
				return CONG_TOPIC_OK;
			}
		}else{
			/* pattern[0] == sub[0] */
			if(sub[1] == 0){
				if(pattern[1] == '/'
						&& pattern[2] == '#'
						&& pattern[3] == 0){
					*result = true;
					return CONG_TOPIC_OK;
				}
			}
			apos++;
			pattern++;
			sub++;
			if(pattern[0] == 0 && sub[0] == 0){
				*result = true;
				return CONG_TOPIC_OK;
			}else if(sub[0] == 0 && pattern[0] == '+' && pattern[1] == 0){
				if(whole_level_ok(pattern, apos == 0) != CONG_TOPIC_OK)
					return CONG_TOPIC_EINVAL;
				*result = true;
				return CONG_TOPIC_OK;
			}
		}
	}
	/* Out of the loop only when the rule ran out while the subscription still had
	 * bytes left, which is the same as "not covered". */
	return CONG_TOPIC_OK;
}
