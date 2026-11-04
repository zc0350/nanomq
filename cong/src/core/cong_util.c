#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/stat.h>

#include "cong_core.h"

#define CONG_MAX_FILE_BYTES (16u * 1024u * 1024u)

static cong_log_fn log_callback = NULL;

void cong_set_logger(cong_log_fn fn)
{
	log_callback = fn;
}

void cong_log(int level, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	if(log_callback){
		log_callback(level, fmt, args);
	}else{
		fprintf(stderr, "cong-plugin: ");
		vfprintf(stderr, fmt, args);
	}
	va_end(args);
}

char *cong_read_file(const char *path, size_t *filelen)
{
	FILE *f;
	long size;
	size_t read;
	char *buf;

	f = fopen(path, "rb");
	if(!f){
		cong_log(CONG_LOG_ERR, "cannot open \"%s\": %s", path, strerror(errno));
		return NULL;
	}
	if(fseek(f, 0, SEEK_END) != 0){
		fclose(f);
		cong_log(CONG_LOG_ERR, "cannot seek in \"%s\": %s", path, strerror(errno));
		return NULL;
	}
	size = ftell(f);
	if(size < 0){
		fclose(f);
		cong_log(CONG_LOG_ERR, "cannot size \"%s\": %s", path, strerror(errno));
		return NULL;
	}
	if((unsigned long) size > CONG_MAX_FILE_BYTES){
		fclose(f);
		cong_log(CONG_LOG_ERR, "\"%s\" is %ld bytes, the limit is %u",
				path, size, CONG_MAX_FILE_BYTES);
		return NULL;
	}
	if(fseek(f, 0, SEEK_SET) != 0){
		fclose(f);
		cong_log(CONG_LOG_ERR, "cannot rewind \"%s\": %s", path, strerror(errno));
		return NULL;
	}

	buf = malloc((size_t) size + 1);
	if(!buf){
		fclose(f);
		cong_log(CONG_LOG_ERR, "out of memory reading \"%s\"", path);
		return NULL;
	}
	read = fread(buf, 1, (size_t) size, f);
	fclose(f);
	if(read != (size_t) size){
		free(buf);
		cong_log(CONG_LOG_ERR, "\"%s\": short read", path);
		return NULL;
	}
	buf[read] = '\0';

	if(filelen){
		*filelen = read;
	}
	return buf;
}

bool cong_subject_compile(struct cong_subject *subject, const char *value,
		const char *match, bool want_groups, const char *who, const char *path, unsigned lineno)
{
	int flags;
	int rc;

	memset(subject, 0, sizeof(struct cong_subject));

	if(match == NULL || !strcmp(match, "exact")){
		if(!strcmp(value, "*")){
			subject->kind = CONG_MATCH_ANY;
		}else{
			subject->kind = CONG_MATCH_EXACT;
		}
	}else if(!strcmp(match, "any")){
		subject->kind = CONG_MATCH_ANY;
	}else if(!strcmp(match, "regex")){
		subject->kind = CONG_MATCH_REGEX;
	}else{
		cong_log(CONG_LOG_ERR, "%s:%u: %s has unknown \"match\" \"%s\", expected \"exact\", \"regex\" or \"any\"",
				path, lineno, who, match);
		return false;
	}

	if(subject->kind == CONG_MATCH_REGEX){
		/* REG_NOSUB is the fast path: without it regcomp() builds the capture
		 * bookkeeping and regexec() has to fill an array. */
		flags = REG_EXTENDED;
		if(!want_groups){
			flags |= REG_NOSUB;
		}
		rc = regcomp(&subject->pattern, value, flags);
		if(rc != 0){
			char errbuf[256];
			regerror(rc, &subject->pattern, errbuf, sizeof(errbuf));
			cong_log(CONG_LOG_ERR, "%s:%u: %s is not a valid POSIX extended regular expression (\"%s\"): %s",
					path, lineno, who, value, errbuf);
			return false;
		}
		subject->grouped = want_groups;
		if(want_groups){
			subject->ngroups = (int) subject->pattern.re_nsub;
			if(subject->ngroups > CONG_MAX_GROUPS - 1){
				cong_log(CONG_LOG_ERR, "%s:%u: %s has %d capture groups, the limit is %d",
						path, lineno, who, subject->ngroups, CONG_MAX_GROUPS - 1);
				regfree(&subject->pattern);
				memset(subject, 0, sizeof(struct cong_subject));
				return false;
			}
		}
	}

	subject->raw = strdup(value);
	if(!subject->raw){
		if(subject->kind == CONG_MATCH_REGEX){
			regfree(&subject->pattern);
			memset(subject, 0, sizeof(struct cong_subject));
		}
		cong_log(CONG_LOG_ERR, "%s:%u: out of memory", path, lineno);
		return false;
	}
	return true;
}

bool cong_subject_match(const struct cong_subject *subject, const char *value)
{
	switch(subject->kind){
		case CONG_MATCH_ANY:
			return true;
		case CONG_MATCH_EXACT:
			return value && !strcmp(value, subject->raw);
		case CONG_MATCH_REGEX:
			return value && regexec(&subject->pattern, value, 0, NULL, 0) == 0;
	}
	return false;
}

bool cong_subject_match_groups(const struct cong_subject *subject, const char *value,
		struct cong_groups *groups)
{
	regmatch_t matches[CONG_MAX_GROUPS];
	size_t i;

	groups->count = 0;
	if(!value || !subject->grouped || subject->kind != CONG_MATCH_REGEX){
		return false;
	}
	if(regexec(&subject->pattern, value, CONG_MAX_GROUPS, matches, 0) != 0){
		return false;
	}
	/* Group 0 is the whole match. POSIX leaves unmatched optional groups as -1;
	 * those are recorded as empty so a template can never read stale offsets. */
	for(i = 0; i < (size_t) CONG_MAX_GROUPS; i++){
		if(matches[i].rm_so < 0 || (size_t) matches[i].rm_eo > strlen(value)){
			groups->g[i].text = NULL;
			groups->g[i].len = 0;
		}else{
			groups->g[i].text = value + matches[i].rm_so;
			groups->g[i].len = (size_t) (matches[i].rm_eo - matches[i].rm_so);
		}
	}
	groups->count = (size_t) subject->ngroups;
	return true;
}

void cong_subject_free(struct cong_subject *subject)
{
	if(subject->kind == CONG_MATCH_REGEX){
		regfree(&subject->pattern);
	}
	free(subject->raw);
	memset(subject, 0, sizeof(struct cong_subject));
}

bool cong_subject_from_json(const cJSON *record, const char *key, const char *match_key,
		struct cong_subject *subject, bool want_groups, const char *path, unsigned lineno)
{
	const cJSON *item;
	const char *value, *match;

	item = cJSON_GetObjectItemCaseSensitive(record, key);
	if(!item){
		/* No subject at all means "any". A "match" without a subject to apply to
		 * is a typo waiting to weaken a rule, so refuse it. */
		if(match_key && cJSON_GetObjectItemCaseSensitive(record, match_key)){
			cong_log(CONG_LOG_ERR, "%s:%u: \"%s\" is set but \"%s\" is missing, so which one applies is undefined",
					path, lineno, match_key, key);
			return false;
		}
		return cong_subject_compile(subject, "*", NULL, false, key, path, lineno);
	}

	value = cong_json_string(item);
	if(!value){
		cong_log(CONG_LOG_ERR, "%s:%u: \"%s\" must be a string", path, lineno, key);
		return false;
	}

	match = NULL;
	if(match_key){
		item = cJSON_GetObjectItemCaseSensitive(record, match_key);
		if(item){
			match = cong_json_string(item);
			if(!match){
				cong_log(CONG_LOG_ERR, "%s:%u: \"%s\" must be a string", path, lineno, match_key);
				return false;
			}
		}
	}

	return cong_subject_compile(subject, value, match, want_groups, key, path, lineno);
}

/* A substituted identity must not carry MQTT wildcards, or a clientid of "a/#"
 * would widen the rule it is substituted into. The broker does not do this for
 * us: its deny_special_chars gate only runs on the legacy v2/v3/v4 plugin APIs,
 * and on the v5 event path this plugin registers on, both 2.0.21 (src/security.c)
 * and 2.1.2 (src/plugin_acl_check.c) still carry the upstream "FIXME - username
 * deny special chars" comment. */
static bool expand_value_ok(const char *text, size_t len)
{
	size_t i;

	for(i = 0; i < len; i++){
		if(text[i] == '+' || text[i] == '#'){
			return false;
		}
	}
	return true;
}

enum cong_expand_result cong_topic_expand(char *out, size_t outsize, const char *pattern,
		const char *clientid, const char *username, const struct cong_groups *groups)
{
	const char *value = NULL;
	size_t used = 0, value_len = 0;
	bool copying = true;
	const char *p = pattern;

	if(outsize == 0){
		return CONG_EXPAND_TOOLONG;
	}
	while(*p){
		value = NULL;
		value_len = 0;
		copying = true;

		if(p[0] == '%'){
			if(p[1] == '%'){
				value = "%";
				value_len = 1;
				p += 2;
			}else if(p[1] == 'c' || p[1] == 'u'){
				value = (p[1] == 'c') ? clientid : username;
				if(!value || value[0] == '\0'){
					/* Like the broker: a missing identity matches nothing, rather
					 * than matching an empty level. */
					return CONG_EXPAND_NO_MATCH;
				}
				value_len = strlen(value);
				p += 2;
			}else if(p[1] >= '0' && p[1] <= '9'){
				if(!groups){
					return CONG_EXPAND_NO_CAPTURES;
				}
				value = groups->g[p[1] - '0'].text;
				value_len = groups->g[p[1] - '0'].len;
				if(!value){
					/* An optional group that did not participate in the match. */
					return CONG_EXPAND_NO_MATCH;
				}
				p += 2;
			}else{
				/* Not one of our tokens, e.g. "sales/50%off" - keep it verbatim. */
				value = "%";
				value_len = 1;
				p += 1;
			}
			copying = false;
		}else{
			value = p;
			value_len = 1;
			p += 1;
		}

		if(!copying && !expand_value_ok(value, value_len)){
			return CONG_EXPAND_WILDCARD;
		}
		if(used + value_len >= outsize){
			return CONG_EXPAND_TOOLONG;
		}
		memcpy(out + used, value, value_len);
		used += value_len;
	}
	out[used] = '\0';
	return CONG_EXPAND_OK;
}

/* Unwraps "::ffff:a.b.c.d" into a plain IPv4 address. */
static bool net_unmap(sa_family_t *family, uint8_t *addr)
{
	static const uint8_t prefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

	if(*family != AF_INET6){
		return false;
	}
	if(memcmp(addr, prefix, sizeof(prefix)) != 0){
		return false;
	}
	*family = AF_INET;
	memmove(addr, addr + 12, 4);
	return true;
}

bool cong_net_parse(struct cong_net *net, const char *text, const char *who,
		const char *path, unsigned lineno)
{
	char host[64];
	const char *slash;
	char *endptr;
	size_t host_len;
	long prefix;
	sa_family_t family;

	memset(net, 0, sizeof(struct cong_net));

	slash = strchr(text, '/');
	if(slash){
		host_len = (size_t) (slash - text);
	}else{
		host_len = strlen(text);
	}
	if(host_len == 0 || host_len >= sizeof(host)){
		cong_log(CONG_LOG_ERR, "%s:%u: %s has an invalid address \"%s\"", path, lineno, who, text);
		return false;
	}
	memcpy(host, text, host_len);
	host[host_len] = '\0';

	family = AF_INET;
	if(inet_pton(AF_INET, host, net->addr) == 1){
		/* ok */
	}else{
		family = AF_INET6;
		if(inet_pton(AF_INET6, host, net->addr) != 1){
			cong_log(CONG_LOG_ERR, "%s:%u: %s is neither an IPv4 nor an IPv6 address (\"%s\")",
					path, lineno, who, text);
			return false;
		}
		net_unmap(&family, net->addr);
	}
	net->family = family;

	if(!slash){
		net->prefix = (family == AF_INET) ? 32 : 128;
		return true;
	}

	net->cidr = true;
	errno = 0;
	endptr = NULL;
	prefix = strtol(slash + 1, &endptr, 10);
	if(errno != 0 || endptr == slash + 1 || (endptr && *endptr != '\0') || prefix < 0){
		cong_log(CONG_LOG_ERR, "%s:%u: %s has a prefix that is not a number in \"%s\"",
				path, lineno, who, text);
		return false;
	}
	if(prefix > (family == AF_INET ? 32 : 128)){
		cong_log(CONG_LOG_ERR, "%s:%u: %s has a prefix length out of range in \"%s\"",
				path, lineno, who, text);
		return false;
	}
	net->prefix = (uint8_t) prefix;
	/* Ignore host bits so that 192.168.1.57/24 behaves as 192.168.1.0/24. */
	{
		unsigned bytes = net->prefix / 8;
		unsigned bits = net->prefix % 8;
		if(bits > 0){
			net->addr[bytes] &= (uint8_t) (0xffu << (8 - bits));
			bytes++;
		}
		for(unsigned i = bytes; i < 16; i++){
			net->addr[i] = 0;
		}
	}
	return true;
}

bool cong_net_match(const struct cong_net *net, const char *addr_text)
{
	uint8_t addr[16];
	sa_family_t family;
	unsigned bytes, bits;

	if(!addr_text){
		return false;
	}

	family = AF_INET;
	if(inet_pton(AF_INET, addr_text, addr) == 1){
		/* ok */
	}else if(inet_pton(AF_INET6, addr_text, addr) == 1){
		family = AF_INET6;
		net_unmap(&family, addr);
	}else{
		return false;
	}

	if(family != net->family){
		return false;
	}

	bytes = net->prefix / 8;
	bits = net->prefix % 8;
	if(memcmp(addr, net->addr, bytes) != 0){
		return false;
	}
	if(bits > 0){
		uint8_t mask = (uint8_t) (0xffu << (8 - bits));
		if((addr[bytes] & mask) != (net->addr[bytes] & mask)){
			return false;
		}
	}
	return true;
}

static bool alnum_only(char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}

size_t cong_sanitize_identity_n(const char *src, size_t srclen, char *dst, size_t dstsize)
{
	size_t kept = 0;
	size_t i;

	for(i = 0; i < srclen; i++){
		if(!alnum_only(src[i])){
			continue;
		}
		if(dst && kept < dstsize){
			dst[kept] = src[i];
		}
		kept++;
	}
	if(dst){
		if(kept >= dstsize){
			return (size_t) -1;
		}
		dst[kept] = '\0';
	}
	return kept;
}

size_t cong_sanitize_identity(const char *src, char *dst, size_t dstsize)
{
	return cong_sanitize_identity_n(src, strlen(src), dst, dstsize);
}

static int hex_digit(char c)
{
	if(c >= '0' && c <= '9'){
		return c - '0';
	}
	if(c >= 'a' && c <= 'f'){
		return c - 'a' + 10;
	}
	if(c >= 'A' && c <= 'F'){
		return c - 'A' + 10;
	}
	return -1;
}

int cong_hex_decode(const char *hex, size_t hexlen, uint8_t *out, size_t outsize, size_t *outlen)
{
	size_t i;

	if(hexlen % 2 != 0){
		return 1;
	}
	if(hexlen / 2 > outsize){
		return 2;
	}
	for(i = 0; i < hexlen; i += 2){
		int hi = hex_digit(hex[i]);
		int lo = hex_digit(hex[i + 1]);
		if(hi < 0 || lo < 0){
			return 3;
		}
		out[i / 2] = (uint8_t) ((hi << 4) | lo);
	}
	if(outlen){
		*outlen = hexlen / 2;
	}
	return 0;
}

bool cong_json_bool(const cJSON *item, bool *value)
{
	const char *text;

	if(cJSON_IsTrue(item)){
		*value = true;
		return true;
	}
	if(cJSON_IsFalse(item)){
		*value = false;
		return true;
	}
	text = cong_json_string(item);
	if(text){
		if(!strcmp(text, "true")){
			*value = true;
			return true;
		}
		if(!strcmp(text, "false")){
			*value = false;
			return true;
		}
	}
	return false;
}

const char *cong_json_string(const cJSON *item)
{
	if(!cJSON_IsString(item)){
		return NULL;
	}
	return item->valuestring;
}

bool cong_json_check_keys(const cJSON *record, const char *const *allowed,
		const char *what, const char *path, unsigned lineno)
{
	const cJSON *child;
	const cJSON *earlier;
	bool known;

	for(child = record->child; child; child = child->next){
		if(!child->string){
			cong_log(CONG_LOG_ERR, "%s:%u: %s contains something that is not a key/value pair",
					path, lineno, what);
			return false;
		}
		/* Duplicate keys are legal JSON but are read differently on the two
		 * sides: cJSON_GetObjectItem() returns the first match, while a normal
		 * parser keeps the last. The rule that loads would not be the rule that
		 * was checked, so refuse it instead of picking a side. */
		for(earlier = record->child; earlier != child; earlier = earlier->next){
			if(!strcmp(earlier->string, child->string)){
				cong_log(CONG_LOG_ERR, "%s:%u: %s has the key \"%s\" twice. Refusing to load, because which one applies is not the same on both sides of a rule file.",
						path, lineno, what, child->string);
				return false;
			}
		}
		known = false;
		for(unsigned i = 0; allowed[i]; i++){
			if(!strcmp(child->string, allowed[i])){
				known = true;
				break;
			}
		}
		if(!known){
			cong_log(CONG_LOG_ERR, "%s:%u: %s has an unknown key \"%s\". Refusing to load: a misspelled key would silently weaken this rule.",
					path, lineno, what, child->string);
			return false;
		}
	}
	return true;
}

bool cong_jsonl_parse(const char *path, cong_jsonl_cb cb, void *userdata)
{
	char *buf;
	const char *p, *after, *q;
	unsigned lineno = 1;
	bool ok;

	buf = cong_read_file(path, NULL);
	if(!buf){
		return false;
	}

	p = buf;
	for(;;){
		while(*p == '\n' || *p == ' ' || *p == '\t' || *p == '\r'){
			if(*p == '\n'){
				lineno++;
			}
			p++;
		}
		if(*p == '#'){
			while(*p != '\0' && *p != '\n'){
				p++;
			}
			continue;
		}
		if(*p == '\0'){
			break;
		}

		after = NULL;
		cJSON *record = cJSON_ParseWithOpts(p, &after, false);
		if(!record){
			cong_log(CONG_LOG_ERR, "%s:%u: cannot be read as a JSON object (near \"%.40s\")", path, lineno, p);
			free(buf);
			return false;
		}
		if(!cJSON_IsObject(record)){
			cong_log(CONG_LOG_ERR, "%s:%u: a JSONL rule must be an object", path, lineno);
			cJSON_Delete(record);
			free(buf);
			return false;
		}

		ok = cb(record, lineno, path, userdata);
		cJSON_Delete(record);
		if(!ok){
			free(buf);
			return false;
		}

		for(q = p; q < after; q++){
			if(*q == '\n'){
				lineno++;
			}
		}
		p = after;
	}

	free(buf);
	return true;
}
