#ifndef CONG_CORE_H
#define CONG_CORE_H

/*
 * Cong IoT MQTT plugin - core types and API.
 *
 * This layer deliberately does NOT include any mosquitto header so it can be
 * compiled and unit tested without a broker. The values that must agree with
 * the broker (ACL bit flags, log levels) are mirrored here and checked with
 * _Static_assert in cong_plugin.c.
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#include <regex.h>

#include <cjson/cJSON.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Mirror of MOSQ_ACL_* in mosquitto/broker_plugin.h. */
#define CONG_ACL_NONE 0x00
#define CONG_ACL_READ 0x01
#define CONG_ACL_WRITE 0x02
#define CONG_ACL_SUBSCRIBE 0x04
#define CONG_ACL_UNSUBSCRIBE 0x08
#define CONG_ACL_ALL 0x0F

/* Mirror of the MOSQ_LOG_* bits in mosquitto/defs.h. */
#define CONG_LOG_INFO 0x1
#define CONG_LOG_NOTICE 0x2
#define CONG_LOG_WARNING 0x4
#define CONG_LOG_ERR 0x8
#define CONG_LOG_DEBUG 0x10

enum cong_decision {
	CONG_ALLOW = 0,     /* an allow rule decided it */
	CONG_DENY = 1,      /* an explicit deny rule decided it */
	CONG_NO_MATCH = 2,  /* no rule applied - the caller must deny */
	CONG_ERROR = 3      /* internal failure - the caller must deny */
};

enum cong_match_kind {
	CONG_MATCH_ANY,
	CONG_MATCH_EXACT,
	CONG_MATCH_REGEX
};

enum cong_alg {
	CONG_ALG_MD5,
	CONG_ALG_SHA1,
	CONG_ALG_SHA256,
	CONG_ALG_SHA512
};

/* One factor of the pre-image. "scheme" is any ordered list of these, so the
 * three spellings this plugin started with (username+salt, salt+username,
 * salt+username+salt) are just the entries of that list, and clientid joins in
 * on the same terms. Repeats are allowed - salt+username+salt is a repeat.
 * PART_TEXT is what a segment becomes when it is not one of those three words:
 * a template mixing literal text with %uN / %cN references to the capture
 * groups of this rule's username and clientid patterns. That is how
 * "abcde_device1" gets digested as its two halves rather than as one name,
 * which matters because whole-name sanitising is many-to-one and would hand
 * "abcd_edevice1" the same password. */
enum cong_scheme_part {
	PART_USERNAME,
	PART_CLIENTID,
	PART_SALT,
	PART_TEXT
};

/* Longest scheme we are willing to hold. A rule longer than this is a typo. */
#define CONG_SCHEME_MAX_PARTS 8

struct cong_scheme_item {
	enum cong_scheme_part part;
	char *text;          /* PART_TEXT only: the segment exactly as written */
	bool uses_username;  /* contributes the username, whole or through %uN */
	bool uses_clientid;
	/* Highest group number referenced, 0 when the identity is only used whole.
	 * Non zero is a promise the loader enforces against the compiled pattern. */
	int username_group;
	int clientid_group;
};

struct cong_scheme {
	unsigned count;
	struct cong_scheme_item items[CONG_SCHEME_MAX_PARTS];
};

enum cong_topic_kind {
	CONG_TOPIC_WILDCARD,  /* MQTT +/# semantics, as in the native acl file */
	CONG_TOPIC_EXACT      /* the string is a literal topic, never a pattern */
};

struct cong_subject {
	enum cong_match_kind kind;
	char *raw;       /* the string as written in the file, for logging */
	regex_t pattern; /* only used when kind == CONG_MATCH_REGEX */
	int ngroups;     /* re_nsub when compiled with want_groups, else 0 */
	bool grouped;    /* compiled without REG_NOSUB, so captures are available */
};

/* An IPv4/IPv6 address or CIDR block. */
struct cong_net {
	sa_family_t family;
	uint8_t addr[16];
	uint8_t prefix;    /* bits; 32 for IPv4 and 128 for IPv6 mean a single host */
	bool cidr;
};

/* ---------------------------------------------------------------- logging */

typedef void (*cong_log_fn)(int level, const char *fmt, va_list args);
void cong_set_logger(cong_log_fn fn);
void cong_log(int level, const char *fmt, ...);

/* ------------------------------------------------------------------- util */

char *cong_read_file(const char *path, size_t *filelen);

/* value is the string to match on; match is NULL/"exact"/"regex"/"any".
 * want_groups compiles a regular expression without REG_NOSUB so that
 * cong_subject_match_groups() can return captures; a rule only asks for it
 * when one of its topics references %0..%9, because matching with captures is
 * measurably slower than matching without.
 * who is the field name, used in error messages. Returns false and logs on a
 * bad regular expression. */
bool cong_subject_compile(struct cong_subject *subject, const char *value,
		const char *match, bool want_groups, const char *who, const char *path, unsigned lineno);
/* Reads record[key] and record[match_key]; when the key is absent the subject
 * is built to match anything, which is how an omitted constraint is expressed. */
bool cong_subject_from_json(const cJSON *record, const char *key, const char *match_key,
		struct cong_subject *subject, bool want_groups, const char *path, unsigned lineno);
bool cong_subject_match(const struct cong_subject *subject, const char *value);
void cong_subject_free(struct cong_subject *subject);

/* A captured substring, pointing into the string that was matched. Only valid
 * while that string is. */
struct cong_captured {
	const char *text;
	size_t len;
};

#define CONG_MAX_GROUPS 10  /* index 0 is the whole match, %1..%9 are the groups */

/* Filled by cong_subject_match_groups(). */
struct cong_groups {
	size_t count;
	struct cong_captured g[CONG_MAX_GROUPS];
};

/* Matching that also returns the captures. Returns false when the value does
 * not match, and also when the subject was not compiled with captures (that is
 * a configuration error the ACL loader is expected to reject earlier). */
bool cong_subject_match_groups(const struct cong_subject *subject, const char *value,
		struct cong_groups *groups);

/* ------------------------------------------------------- topic templating */

enum cong_expand_result {
	CONG_EXPAND_OK = 0,
	CONG_EXPAND_NO_MATCH,    /* an identity the pattern needs is absent */
	CONG_EXPAND_TOOLONG,     /* the expanded topic does not fit the buffer */
	CONG_EXPAND_WILDCARD,    /* an expanded value carries + or # */
	CONG_EXPAND_NO_CAPTURES  /* %N referenced but no capture table was supplied */
};

/* The longest expanded pattern we are willing to build. */
#define CONG_EXPANDED_MAX 1024

/* Replaces %c, %u, %0..%9 and %% in a rule topic. The broker's own
 * %c/%u substitution is strictly single level (see
 * libcommon/topic_common.c: "%c" must occupy a whole hierarchy level, and the
 * substituted text is compared character by character only until the topic
 * reaches a "/"), so it can never turn one identity into two levels like
 * "product/device". Doing it here is what lets a username capture expand across
 * levels, and it is also why the expanded values are checked for wildcards:
 * a clientid of "a/#" must not be able to widen the rule.
 * groups may be NULL when the pattern uses no %N reference. */
enum cong_expand_result cong_topic_expand(char *out, size_t outsize, const char *pattern,
		const char *clientid, const char *username, const struct cong_groups *groups);

bool cong_net_parse(struct cong_net *net, const char *text, const char *who,
		const char *path, unsigned lineno);
bool cong_net_match(const struct cong_net *net, const char *addr_text);

/* Copies src to dst keeping only [A-Za-z0-9]. dst may be NULL, in which case
 * only the length is computed. Returns the number of bytes written, or
 * (size_t)-1 if dst is too small.
 * Applies to any identity that enters a digest: one per-rule "sanitize" switch
 * covers both the username and the clientid, so that a rule cannot end up with
 * the two halves of one device identity normalised differently. */
size_t cong_sanitize_identity(const char *src, char *dst, size_t dstsize);

/* The same cleaning for a substring that is not terminated, which is what a
 * capture group of a broker-supplied string is. Same contract as above. */
size_t cong_sanitize_identity_n(const char *src, size_t srclen, char *dst, size_t dstsize);

int cong_hex_decode(const char *hex, size_t hexlen, uint8_t *out, size_t outsize,
		size_t *outlen);

/* Strict boolean: accepts true/false JSON booleans and the strings
 * "true"/"false". Returns false if the item is neither. */
bool cong_json_bool(const cJSON *item, bool *value);
const char *cong_json_string(const cJSON *item);

/* Reads path and calls cb once per JSON record, in file order. Blank lines and
 * lines whose first non blank character is '#' are skipped. cb must copy
 * anything it needs: the record is deleted as soon as it returns. Returning
 * false from cb stops the scan, and the callback is expected to have logged the
 * reason. */
typedef bool (*cong_jsonl_cb)(cJSON *record, unsigned lineno, const char *path, void *userdata);
bool cong_jsonl_parse(const char *path, cong_jsonl_cb cb, void *userdata);

/* Rejects records carrying keys the plugin does not know about, so that a typo
 * in a rule can never silently weaken it. */
bool cong_json_check_keys(const cJSON *record, const char *const *allowed,
		const char *what, const char *path, unsigned lineno);

/* ----------------------------------------------------------------- digest */

bool cong_alg_parse(const char *text, enum cong_alg *alg);
size_t cong_alg_digest_len(enum cong_alg alg);

/* Parses a scheme: a "+"-joined list of one to CONG_SCHEME_MAX_PARTS segments.
 * "+" is reserved as the separator, so it can never appear in the pre-image.
 * A segment equal to "username", "clientid" or "salt" contributes that whole
 * factor; any other segment is a template of literal text plus %uN and %cN
 * group references, where N is 1..9 and the letter names the pattern the group
 * comes from. "%%" is a literal percent. Anything else after a percent - "%u"
 * with no number, "%u0", a bare "%1", "%x" - is refused, because a secret
 * template that silently keeps an unknown token is a password nobody can
 * reproduce. Returns false (and leaves the scheme empty) on an empty segment,
 * on a trailing "+", and on a list that is too long. */
bool cong_scheme_parse(const char *text, struct cong_scheme *scheme);
void cong_scheme_free(struct cong_scheme *scheme);

/* What a whole scheme asks of the connection and of the rule's own patterns. */
struct cong_scheme_use {
	bool username;
	bool clientid;
	bool salt;
	int username_groups;  /* highest %uN referenced, 0 when none */
	int clientid_groups;
};
void cong_scheme_usage(const struct cong_scheme *scheme, struct cong_scheme_use *use);

/* Renders one PART_TEXT segment. *out is malloc'd, holds exactly the bytes this
 * segment contributes, and is NUL terminated only so that a debugger can read
 * it - the length, not the terminator, is what enters the digest.
 * A group that did not participate in the match contributes nothing, which is
 * what makes an optional group usable: the caller must not mistake "absent" for
 * "the connection sent nothing", so this never returns a failure for that.
 * sanitize cleans every substituted group value; the literal text of a template
 * is never cleaned, or a separator of "_" would delete itself.
 * The group tables may be NULL when the segment references nothing.
 * Returns false when the item is not a template segment - a caller that built
 * the parts list wrong - and on out of memory. A malformed template never gets
 * here, because cong_scheme_parse() has already refused the whole file. */
bool cong_scheme_text_build(const struct cong_scheme_item *item, bool sanitize,
		const struct cong_groups *user_groups, const struct cong_groups *client_groups,
		char **out, size_t *outlen);

struct cong_digest_part {
	const uint8_t *data;
	size_t len;
};

/* Digests the parts in the order given. A part with data == NULL is skipped,
 * which keeps an optional factor from shifting the ones after it. */
int cong_digest_parts(enum cong_alg alg, uint8_t *out, size_t outsize, size_t *outlen,
		const struct cong_digest_part *parts, unsigned part_count);

/* Constant time comparison of len bytes. */
int cong_secret_cmp(const uint8_t *a, const uint8_t *b, size_t len);

/* ------------------------------------------------------------------- auth */

struct cong_auth_rule {
	struct cong_subject user;      /* absent in the file means "any" */
	struct cong_subject clientid;  /* absent in the file means "any" */
	struct cong_net ip;
	bool has_ip;
	char *salt;                      /* required; a scheme that ignores it warns at load */
	size_t salt_len;
	enum cong_alg alg;
	struct cong_scheme scheme;       /* which factors, in which order */
	bool sanitize;                   /* applies to username, clientid and their groups */
	unsigned lineno;
	struct cong_auth_rule *next;
};

struct cong_auth_table {
	struct cong_auth_rule *rules;   /* file order */
	size_t rule_count;
	size_t regex_count;
};

struct cong_auth_table *cong_auth_load(const char *path);
void cong_auth_free(struct cong_auth_table *table);
/* Frees a rule chain that is not yet wrapped in a table. */
void cong_auth_free_from_rules(struct cong_auth_rule *rule);

/* password is the raw bytes from the CONNECT packet, which for this plugin is
 * always a lower- or upper-case hex digest. matched_lineno may be NULL.
 * username and clientid are both constraints and, when the rule's scheme names
 * them, digest factors: a rule whose scheme needs a factor the connection does
 * not carry cannot verify, so such a rule is skipped rather than digested with
 * an empty string. */
enum cong_decision cong_auth_check(const struct cong_auth_table *table,
		const char *username, const char *clientid, const char *client_ip,
		const char *password, size_t password_len, unsigned *matched_lineno);

/* -------------------------------------------------------------------- acl */

struct cong_topic {
	char *pattern;
	enum cong_topic_kind kind;
	bool needs_expand;    /* contains a % token that has to be substituted */
	bool needs_captures;  /* references %0..%9, so the rule's user regex must capture */
	int max_group;        /* highest %N with N>=1; a "%0" only rule leaves it 0 */
	struct cong_topic *next;
};

struct cong_acl_rule {
	bool allow;
	int access_mask;
	struct cong_subject user;      /* absent in the file means "any" */
	struct cong_subject clientid;  /* absent in the file means "any" */
	struct cong_net ip;
	bool has_ip;
	struct cong_topic *topics;  /* NULL means "any topic" */
	unsigned lineno;
	struct cong_acl_rule *next;
};

struct cong_acl_table {
	struct cong_acl_rule *rules;
	size_t rule_count;
};

/* MQTT wildcard matching in the two directions a rule file needs. Both return
 * CONG_TOPIC_OK, or CONG_TOPIC_EINVAL when the input is refused outright - a
 * wildcard that does not own its whole level, or a publish topic that carries
 * wildcards at all. Refusal is not the same as "no match": the ACL layer reports
 * it as CONG_ERROR, so a malformed rule fails loudly instead of quietly
 * allowing nothing. Implemented here rather than borrowed from the broker so
 * that one .so means one set of wildcard rules on 2.0.21 and on 2.1.x alike. */
enum cong_topic_rc {
	CONG_TOPIC_OK = 0,
	CONG_TOPIC_EINVAL = 1
};

int cong_topic_matches_sub(const char *pattern, const char *topic, bool *result);
int cong_sub_matches_acl(const char *pattern, const char *sub, bool *result);

/* The topic matcher is injected so the ACL engine stays free of any broker call
 * and the two directions can be swapped in tests; the shipping plugin passes the
 * two functions above. Templating happens above them, in cong_topic_expand(). */
struct cong_topic_ops {
	int (*match_topic)(const char *acl_pattern, const char *topic, bool *result);
	int (*match_subscribe)(const char *acl_pattern, const char *sub, bool *result);
};

struct cong_acl_table *cong_acl_load(const char *path);
void cong_acl_free(struct cong_acl_table *table);
/* Frees a rule chain that is not yet wrapped in a table. */
void cong_acl_free_from_rules(struct cong_acl_rule *rule);

enum cong_decision cong_acl_check(const struct cong_acl_table *table,
		const struct cong_topic_ops *ops, int access, const char *topic,
		const char *username, const char *clientid, const char *client_ip,
		unsigned *matched_lineno);

#ifdef __cplusplus
}
#endif

#endif
