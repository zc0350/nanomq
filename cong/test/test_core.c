#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cong_core.h"

/*
 * core 层的单元测试：不链接 mosquitto，只需要 libcjson、libcrypto 和 libc。
 *
 * 主题匹配已经搬进 src/core/cong_topic.c，本仓库不再借 broker 的匹配函数。对上游
 * 真函数的逐对差分在 Mosquitto 那一侧的仓库里跑（make diffcheck，它要那两棵源码
 * 树），这里留的是同一份实现的回归网。下面的 fake 是第二实现，作用是让 ACL 引擎
 * 别和某一个匹配器绑死：通配符必须独占一级、# 必须是最后一级、具体主题不能带通配
 * 符、$ 层级不互通，这些约束它都保留。期望摘要值由 tools/cong_pwgen.py 独立算出，
 * 避免自证。
 */

static int failures = 0;
static int checks = 0;

#define EXPECT(cond, ...) do { \
		checks++; \
		if(!(cond)){ \
			failures++; \
			printf("  FAIL %s:%d: ", __FILE__, __LINE__); \
			printf(__VA_ARGS__); \
			printf("\n"); \
		} \
	}while(0)

static const char *const AUTH_RULES =
		"# dashboard: sha256(salt + username)\n"
		"{\"username\":\"dashboard\",\"salt\":\"c0ng-2026\",\"alg\":\"sha256\",\"scheme\":\"salt+username\"}\n"
		"# aaaa_* devices: md5(cleaned username + salt)\n"
		"{\"username\":\"^aaaa_[a-z0-9]+$\",\"match\":\"regex\",\"salt\":\"d3v1c3\",\"alg\":\"md5\",\"scheme\":\"username+salt\"}\n"
		"# gateway: username regex AND clientid regex AND source network\n"
		"{\"username\":\"^gw_.*\",\"match\":\"regex\",\"clientid\":\"^gw-[0-9A-F]{8}$\",\"clientid_match\":\"regex\",\"ip\":\"10.0.0.0/8\",\"salt\":\"gtw\",\"alg\":\"sha512\",\"scheme\":\"salt+username+salt\"}\n"
		"# legacy keeps the underscore in the digest\n"
		"{\"username\":\"legacy_x\",\"salt\":\"old\",\"alg\":\"sha1\",\"scheme\":\"username+salt\",\"sanitize\":false}\n"
		"# pump: username AND clientid are both part of the digest\n"
		"{\"username\":\"^pump_([0-9]{4})$\",\"match\":\"regex\",\"salt\":\"pl4nt\",\"alg\":\"sha256\",\"scheme\":\"username+clientid+salt\"}\n"
		"# here the clientid alone is the account, so the username is not digested\n"
		"{\"clientid\":\"^PUMP-[0-9]{4}$\",\"clientid_match\":\"regex\",\"salt\":\"pl4nt\",\"alg\":\"sha256\",\"scheme\":\"clientid+salt\"}\n"
		"# split: each half of the username is digested on its own, with the\n"
		"# underscore written as literal text instead of surviving a cleaning\n"
		"{\"username\":\"^([a-z-]+)_([a-z0-9]+)$\",\"match\":\"regex\",\"salt\":\"sp11\",\"alg\":\"sha256\",\"scheme\":\"%u1_%u2+salt\"}\n"
		"# an optional group that did not take part joins as the empty string\n"
		"{\"username\":\"^tag_([a-z]+)_?([0-9]+)?$\",\"match\":\"regex\",\"salt\":\"opt1\",\"alg\":\"md5\",\"scheme\":\"%u1.%u2+salt\"}\n"
		"# clientid groups too, and the order of the segments is the order of the digest\n"
		"{\"clientid\":\"^GW-([0-9A-F]{4})-([0-9A-F]{4})$\",\"clientid_match\":\"regex\",\"salt\":\"gtw\",\"alg\":\"sha256\",\"scheme\":\"%c2+%c1+salt\"}\n";

static const char *const ACL_RULES =
		"{\"effect\":\"allow\",\"user\":\"dashboard\",\"action\":\"subscribe\",\"topics\":[\"$SYS/#\"]}\n"
		"{\"effect\":\"allow\",\"ip\":\"127.0.0.1\",\"action\":\"all\",\"topics\":[\"$SYS/#\",\"#\"]}\n"
		"{\"effect\":\"deny\",\"action\":\"subscribe\",\"topics\":[\"$SYS/#\",{\"eq\":\"#\"},{\"eq\":\"+/#\"}]}\n"
		"{\"effect\":\"allow\",\"user\":\"^aaaa_.*\",\"match\":\"regex\",\"action\":\"publish\",\"topics\":[\"sensor/%c/data\"]}\n"
		"{\"effect\":\"allow\",\"user\":\"^abcde_([a-z0-9]+)$\",\"match\":\"regex\",\"action\":\"publish\",\"topics\":[\"abcde/%1/event\"]}\n"
		"{\"effect\":\"allow\",\"user\":\"^([a-z0-9]+)_abcde$\",\"match\":\"regex\",\"action\":\"publish\",\"topics\":[\"abcde/%1/event\"]}\n"
		"{\"effect\":\"allow\",\"user\":\"^gw_([a-z0-9]+)$\",\"match\":\"regex\",\"action\":\"subscribe\",\"topics\":[\"abcde/%1/#\"]}\n"
		"{\"effect\":\"allow\"}\n";

static const char *const BAD_KEY_RULES =
		"{\"username\":\"x\",\"salt\":\"s\",\"alg\":\"sha256\",\"scheme\":\"salt+username\",\"typo_field\":true}\n";

static const char *const EMPTY_RULES = "# only a comment\n\n";

static void write_rules(const char *path, const char *content)
{
	FILE *f = fopen(path, "wb");
	if(!f){
		printf("  ABORT: cannot write %s\n", path);
		exit(2);
	}
	fputs(content, f);
	fclose(f);
}

/* True when the file is refused outright, which is how every load-time check in
 * this plugin is meant to behave: a rule the broker cannot compute a password
 * for is never loaded "best effort". */
static bool auth_refuses(const char *content)
{
	struct cong_auth_table *table;
	bool refused;

	write_rules("test_refuse.jsonl", content);
	table = cong_auth_load("test_refuse.jsonl");
	remove("test_refuse.jsonl");
	refused = (table == NULL);
	cong_auth_free(table);
	return refused;
}

/* ------------------------------------------------------------------ fake ops */

static char last_op[32];

/* Splits on "/" and requires + and # to each occupy a whole hierarchy level and
 * # to be last, which is what mosquitto_topic_matches_sub() and
 * mosquitto_sub_matches_acl() enforce by returning MOSQ_ERR_INVAL. The ACL layer
 * turns a refusal into CONG_ERROR, so a malformed rule has to fail loudly
 * instead of quietly matching nothing. */
static bool pattern_is_valid(const char *pattern)
{
	const char *p = pattern;
	const char *level;
	size_t len;

	while(*p){
		level = p;
		len = 0;
		while(p[len] != '\0' && p[len] != '/'){
			len++;
		}
		for(size_t i = 0; i < len; i++){
			if(level[i] != '+' && level[i] != '#'){
				continue;
			}
			if(len != 1){
				return false;  /* "+foo", "foo+", "a/+b" are all invalid */
			}
			if(level[i] == '#' && p[len] != '\0'){
				return false;  /* "#" must be the final level */
			}
		}
		p += len;
		if(*p == '/'){
			p++;
		}
	}
	return true;
}

static bool value_has_wildcard(const char *value)
{
	for(const char *p = value; *p; p++){
		if(*p == '+' || *p == '#'){
			return true;
		}
	}
	return false;
}

/* Level by level match of a pattern against a concrete topic. */
static bool fake_topic_match(const char *pattern, const char *topic)
{
	const char *p = pattern, *t = topic;
	size_t len;

	while(*p){
		if(p[0] == '#'){
			return true;  /* "#" also matches its own parent level */
		}
		if(p[0] == '+' && (p[1] == '\0' || p[1] == '/')){
			if(*t == '\0'){
				return false;  /* "+" needs a level to consume */
			}
			while(*t && *t != '/'){
				t++;
			}
			p++;
		}else{
			len = 0;
			while(p[len] != '\0' && p[len] != '/'){
				len++;
			}
			if(strncmp(p, t, len) != 0 || (t[len] != '\0' && t[len] != '/')){
				return false;
			}
			t += len;
			p += len;
		}
		if(*p == '/'){
			p++;
			if(*t == '/'){
				t++;
			}
		}
	}
	return *t == '\0';
}

/* Containment: does the acl pattern cover the whole subscription filter? This is
 * mosquitto_sub_matches_acl() semantics, where "$SYS/#" covers "$SYS/broker/#"
 * but not "#", and "sensor/aaaa/data" does not cover "sensor/#". */
static bool fake_sub_match(const char *pattern, const char *sub)
{
	const char *p = pattern, *t = sub;
	size_t len;

	while(*p){
		if(p[0] == '#'){
			return true;
		}
		len = 0;
		while(t[len] != '\0' && t[len] != '/'){
			len++;
		}
		if(len == 1 && (t[0] == '#' || t[0] == '+')){
			/* The subscription is broader here, so only an identical wildcard
			 * level on the acl side covers it. */
			if(p[0] != t[0] || p[1] == '\0' || p[1] != '/'){
				return false;
			}
			p++;
			t++;
		}else{
			if(strncmp(p, t, len) != 0 || (p[len] != '\0' && p[len] != '/')){
				return false;
			}
			p += len;
			t += len;
		}
		if(*p == '/'){
			p++;
			if(*t == '/'){
				t++;
			}
		}
	}
	return *t == '\0';
}

static int op_topic(const char *pattern, const char *topic, bool *result)
{
	strcpy(last_op, "topic");
	*result = false;
	if(!pattern_is_valid(pattern) || value_has_wildcard(topic)){
		return 1;
	}
	if((pattern[0] == '$') != (topic[0] == '$')){
		return 0;
	}
	*result = fake_topic_match(pattern, topic);
	return 0;
}

static int op_subscribe(const char *pattern, const char *sub, bool *result)
{
	strcpy(last_op, "subscribe");
	*result = false;
	/* 上游的 sub_matches_acl() 只把这套校验用在规则侧，订阅过滤器自己带畸形通配符
	 * 时返回「不匹配」而不是「无效」，所以这里比上游严。走 broker 到不了这一步：
	 * handle_subscribe.c 先 mosquitto_sub_topic_check() 拒掉畸形订阅，才轮到 ACL。 */
	if(!pattern_is_valid(pattern) || !pattern_is_valid(sub)){
		return 1;
	}
	if((pattern[0] == '$') != (sub[0] == '$')){
		return 0;
	}
	*result = fake_sub_match(pattern, sub);
	return 0;
}

static const struct cong_topic_ops ops = {
	op_topic, op_subscribe
};

/* ------------------------------------------------------------------- helpers */

/* One pre-image factor, written as a literal. sizeof() drops the terminating
 * NUL, so a length can never drift away from the text next to it the way a hand
 * written 9 or 8 could. */
#define PART(s) { (const uint8_t *) (s), sizeof(s) - 1 }

static bool digest_is(enum cong_alg alg, const char *hex_expected,
		const struct cong_digest_part *parts, unsigned part_count)
{
	uint8_t got[64];
	uint8_t expected[64];
	size_t got_len = 0;
	size_t expected_len = 0;

	if(cong_digest_parts(alg, got, sizeof(got), &got_len, parts, part_count) != 0){
		return false;
	}
	if(cong_hex_decode(hex_expected, strlen(hex_expected), expected, sizeof(expected), &expected_len) != 0){
		return false;
	}
	return got_len == expected_len && memcmp(got, expected, got_len) == 0;
}

/* Lets a test write the factor list once instead of recounting it by hand. */
#define DIGEST(alg, hex_expected, parts) \
		digest_is((alg), (hex_expected), (parts), sizeof(parts) / sizeof((parts)[0]))

/* --------------------------------------------------------------------- tests */

static void test_sanitize(void)
{
	char buffer[64];

	printf("sanitize\n");
	/* One function, both identities: the auth layer cleans the username and the
	 * clientid with it, under the single per-rule "sanitize" switch. */
	EXPECT(cong_sanitize_identity("aaaa_bbbb", buffer, sizeof(buffer)) == 8, "len wrong");
	EXPECT(!strcmp(buffer, "aaaabbbb"), "got \"%s\"", buffer);

	cong_sanitize_identity("gw-DEADBEEF", buffer, sizeof(buffer));
	EXPECT(!strcmp(buffer, "gwDEADBEEF"), "clientid got \"%s\"", buffer);

	cong_sanitize_identity("a,b|c:d e", buffer, sizeof(buffer));
	EXPECT(!strcmp(buffer, "abcde"), "got \"%s\"", buffer);

	cong_sanitize_identity("", buffer, sizeof(buffer));
	EXPECT(!strcmp(buffer, ""), "empty should stay empty");

	/* A name that is entirely punctuation digests as the empty string, which is
	 * exactly why the rules file must not hand out such usernames. */
	cong_sanitize_identity("___", buffer, sizeof(buffer));
	EXPECT(!strcmp(buffer, ""), "got \"%s\"", buffer);
}

static void test_hex(void)
{
	uint8_t out[64];
	size_t len = 0;

	printf("hex\n");
	EXPECT(cong_hex_decode("00ff7B", 6, out, sizeof(out), &len) == 0, "mixed case must parse");
	EXPECT(len == 3 && out[0] == 0x00 && out[1] == 0xff && out[2] == 0x7b, "bytes wrong");
	EXPECT(cong_hex_decode("0", 1, out, sizeof(out), &len) != 0, "odd length must fail");
	EXPECT(cong_hex_decode("zz", 2, out, sizeof(out), &len) != 0, "non hex must fail");
	EXPECT(cong_hex_decode("0011", 4, out, 1, &len) != 0, "overflow must fail");
}

static void test_net(void)
{
	struct cong_net net;

	printf("net\n");
	EXPECT(cong_net_parse(&net, "127.0.0.1", "ip", "test", 1), "parse 127.0.0.1");
	EXPECT(cong_net_match(&net, "127.0.0.1"), "host should match itself");
	EXPECT(!cong_net_match(&net, "127.0.0.2"), "other host must not match");
	EXPECT(!cong_net_match(&net, "::ffff:127.0.0.2"), "v6 form of another host must not match");

	EXPECT(cong_net_parse(&net, "192.168.1.57/24", "ip", "test", 1), "parse cidr with host bits");
	EXPECT(cong_net_match(&net, "192.168.1.9"), "192.168.1.9 is inside 192.168.1.0/24");
	EXPECT(cong_net_match(&net, "192.168.1.57"), "the written host itself is inside");
	EXPECT(!cong_net_match(&net, "192.168.2.9"), "192.168.2.9 is outside");
	EXPECT(cong_net_match(&net, "::ffff:192.168.1.9"), "ipv4 mapped form should match");

	EXPECT(cong_net_parse(&net, "fd00::/8", "ip", "test", 1), "parse v6 cidr");
	EXPECT(cong_net_match(&net, "fd12::1"), "fd12::1 is inside fd00::/8");
	EXPECT(!cong_net_match(&net, "fe80::1"), "fe80::1 is outside");
	EXPECT(!cong_net_match(&net, "127.0.0.1"), "v4 must not match a v6 rule");

	EXPECT(!cong_net_parse(&net, "not-an-ip", "ip", "test", 1), "garbage must be rejected");
	EXPECT(!cong_net_parse(&net, "10.0.0.0/33", "ip", "test", 1), "prefix out of range must be rejected");
	EXPECT(!cong_net_match(&net, NULL), "NULL address must not match");
}

static void test_subject(void)
{
	struct cong_subject subject;

	printf("subject\n");
	EXPECT(cong_subject_compile(&subject, "dashboard", NULL, false, "username", "test", 1), "compile exact");
	EXPECT(subject.kind == CONG_MATCH_EXACT, "kind");
	EXPECT(cong_subject_match(&subject, "dashboard"), "should match");
	EXPECT(!cong_subject_match(&subject, "Dashboard"), "case sensitive");
	EXPECT(!cong_subject_match(&subject, NULL), "NULL must not match an exact rule");
	cong_subject_free(&subject);

	EXPECT(cong_subject_compile(&subject, "*", NULL, false, "username", "test", 1), "compile star");
	EXPECT(subject.kind == CONG_MATCH_ANY, "\"*\" should mean any");
	EXPECT(cong_subject_match(&subject, NULL), "any matches a missing username");
	cong_subject_free(&subject);

	/* Without want_groups, REG_NOSUB is used: it is the fast path, and ngroups stays 0
	 * even though the pattern itself has no captures either way. */
	EXPECT(cong_subject_compile(&subject, "^aaaa_([a-z0-9]+)$", "regex", false, "username", "test", 1), "compile regex");
	EXPECT(subject.ngroups == 0, "REG_NOSUB must not count captures");
	EXPECT(!subject.grouped, "not grouped");
	EXPECT(cong_subject_match(&subject, "aaaa_bbbb"), "aaaa_bbbb should match");
	EXPECT(cong_subject_match(&subject, "aaaa_cccc"), "aaaa_cccc should match");
	EXPECT(!cong_subject_match(&subject, "bbbb_aaaa"), "anchored pattern should reject");
	EXPECT(!cong_subject_match(&subject, "aaaa_"), "empty suffix should reject");
	cong_subject_free(&subject);

	/* With want_groups, the same pattern keeps its captures for the topic expander. */
	EXPECT(cong_subject_compile(&subject, "^aaaa_([a-z0-9]+)$", "regex", true, "username", "test", 1), "compile grouped regex");
	EXPECT(subject.grouped, "grouped");
	EXPECT(subject.ngroups == 1, "one capture");
	{
		struct cong_groups groups;
		EXPECT(cong_subject_match_groups(&subject, "aaaa_bbbb", &groups), "grouped match");
		EXPECT(groups.count == 1, "group count");
		EXPECT(groups.g[1].len == 4 && !memcmp(groups.g[1].text, "bbbb", 4), "group 1 is the device part");
		EXPECT(!cong_subject_match_groups(&subject, "bbbb_aaaa", &groups), "grouped reject");
	}
	cong_subject_free(&subject);

	/* regcomp() is POSIX ERE: a "+" with nothing in front is invalid, and that has
	 * to fail the whole load rather than silently match nothing. */
	EXPECT(!cong_subject_compile(&subject, "+invalid", "regex", false, "username", "test", 1), "bad regex must fail");
}

static void test_digest_vectors(void)
{
	/* sha256("c0ng-2026" + "dashboard") */
	static const struct cong_digest_part salt_user[] = { PART("c0ng-2026"), PART("dashboard") };
	/* md5("aaaabbbb" + "d3v1c3") - the username is the sanitized one */
	static const struct cong_digest_part user_salt[] = { PART("aaaabbbb"), PART("d3v1c3") };
	/* sha512("gtw" + "gw01" + "gtw") */
	static const struct cong_digest_part salt_user_salt[] = { PART("gtw"), PART("gw01"), PART("gtw") };
	/* sha1("legacy_x" + "old") - sanitize off, underscore kept */
	static const struct cong_digest_part unsanitized[] = { PART("legacy_x"), PART("old") };
	/* sha256("pump0007" + "PUMP0007" + "pl4nt") - both identities are cleaned */
	static const struct cong_digest_part user_client_salt[] = { PART("pump0007"), PART("PUMP0007"), PART("pl4nt") };
	/* sha256("PUMP0007" + "pl4nt") */
	static const struct cong_digest_part client_salt[] = { PART("PUMP0007"), PART("pl4nt") };
	/* the same factors in another order are a different password */
	static const struct cong_digest_part client_user_salt[] = { PART("PUMP0007"), PART("pump0007"), PART("pl4nt") };
	/* Whole-name cleaning is a many-to-one map, and that is the reason a scheme
	 * can address the halves instead: "abcde_device1" and "abcd_edevice1" both
	 * clean to "abcdedevice1", so one username+salt rule hands them one password. */
	static const struct cong_digest_part cleaned_whole[] = { PART("abcdedevice1"), PART("sp11") };
	/* "%u1_%u2+salt" keeps the underscore as literal text and digests the two
	 * halves as they were, which is two different passwords for two devices. */
	static const struct cong_digest_part split_first[] = { PART("abcde_device1"), PART("sp11") };
	static const struct cong_digest_part split_second[] = { PART("abcd_edevice1"), PART("sp11") };

	printf("digest vectors (from tools/cong_pwgen.py)\n");

	EXPECT(DIGEST(CONG_ALG_SHA256, "c45c09aa5760a3562c35b01e8b6351b79bde1d51c3af408ddc92c9523328b9de", salt_user),
			"sha256 salt+username");
	EXPECT(DIGEST(CONG_ALG_MD5, "67b1d9a71df8f6b6aaf0a6e0a99e58eb", user_salt),
			"md5 username+salt");
	EXPECT(DIGEST(CONG_ALG_SHA512,
			"9f2cf6d121fc7f8a1d927ad3235673095d8386bb10c1a414c167f96ee4cd4cb7"
			"7e58a7f40be4830ce70834a6ba490bbb2dcbed2a2192e909f285a66a64802916", salt_user_salt),
			"sha512 salt+username+salt");
	EXPECT(DIGEST(CONG_ALG_SHA1, "3f7a5dbd0e6174171dc78456b90ed7b0793e1410", unsanitized),
			"sha1 username+salt, unsanitized");
	EXPECT(DIGEST(CONG_ALG_SHA256, "e260f5e0e3ef64677147888d16deb018fc69c67aa008607d62e0e87ed0f064da", user_client_salt),
			"sha256 username+clientid+salt");
	EXPECT(DIGEST(CONG_ALG_SHA256, "982a8647c5a8ef9b6c63c0ae45704e21a003d623ae8435db72855f2a56682127", client_salt),
			"sha256 clientid+salt");
	/* Order is part of the contract, not an implementation detail: a device that
	 * concatenates in the wrong order must not be able to log in. */
	EXPECT(!DIGEST(CONG_ALG_SHA256, "e260f5e0e3ef64677147888d16deb018fc69c67aa008607d62e0e87ed0f064da", client_user_salt),
			"clientid first must be a different digest");

	/* Both halves of the collision, spelled out: one cleaned whole name is one
	 * password (9b54bb...), while the two split pre-images are not. */
	EXPECT(DIGEST(CONG_ALG_SHA256, "9b54bbbdbe4dd2a86bcfc1be3b20041f4df38685a3fef0e24090e29f936495d3", cleaned_whole),
			"sha256 of the cleaned whole name");
	EXPECT(DIGEST(CONG_ALG_SHA256, "48282547c287b53788604b2067d5f3230891196af4471bb7d7507047f6d4c0c0", split_first),
			"sha256 of the split abcde_device1 name");
	EXPECT(DIGEST(CONG_ALG_SHA256, "81cfe26ffa043cc7b3a2d6722d590600a01be76c47c1f9b9dc9c87d5415ce6c3", split_second),
			"sha256 of the split abcd_edevice1 name");
	EXPECT(!DIGEST(CONG_ALG_SHA256, "48282547c287b53788604b2067d5f3230891196af4471bb7d7507047f6d4c0c0", split_second),
			"the two devices must not share the split password");

	EXPECT(cong_alg_digest_len(CONG_ALG_MD5) == 16, "md5 length");
	EXPECT(cong_alg_digest_len(CONG_ALG_SHA1) == 20, "sha1 length");
	EXPECT(cong_alg_digest_len(CONG_ALG_SHA256) == 32, "sha256 length");
	EXPECT(cong_alg_digest_len(CONG_ALG_SHA512) == 64, "sha512 length");

	{
		enum cong_alg alg;
		struct cong_scheme scheme;

		EXPECT(cong_alg_parse("sha256", &alg) && alg == CONG_ALG_SHA256, "alg parse");
		EXPECT(!cong_alg_parse("SHA256", &alg), "alg names are lower case only");
		EXPECT(!cong_alg_parse("md4", &alg), "unknown alg");

		/* The three spellings the plugin started with are sentences of a grammar,
		 * not the whole language: any order, any subset, repeats allowed. Items are
		 * what the loader stores now, so the assertions read the same list. */
		EXPECT(cong_scheme_parse("salt+username+salt", &scheme) && scheme.count == 3
				&& scheme.items[0].part == PART_SALT && scheme.items[1].part == PART_USERNAME
				&& scheme.items[2].part == PART_SALT, "scheme parse");
		EXPECT(cong_scheme_parse("username+clientid+salt", &scheme) && scheme.count == 3
				&& scheme.items[1].part == PART_CLIENTID, "clientid joins the list");
		EXPECT(cong_scheme_parse("salt+salt+username", &scheme) && scheme.count == 3, "repeats are legal");
		EXPECT(cong_scheme_parse("clientid", &scheme) && scheme.count == 1, "one factor is a scheme");
		EXPECT(cong_scheme_parse("salt+clientid+salt+clientid+username+clientid+username+salt", &scheme)
				&& scheme.count == CONG_SCHEME_MAX_PARTS, "the longest legal scheme");
		EXPECT(!cong_scheme_parse("", &scheme), "empty scheme");
		EXPECT(!cong_scheme_parse("username++salt", &scheme), "an empty factor is refused, not read as empty text");
		EXPECT(!cong_scheme_parse("username+", &scheme), "trailing separator");
		/* An unrecognised word is no longer a refusal: since a segment may be a
		 * template over the groups, "user" now reads as the constant text "user".
		 * That is exactly why the loader warns about a segment that only looks like
		 * a misspelled factor - a typo here silently becomes part of the pre-image. */
		EXPECT(cong_scheme_parse("user+salt", &scheme) && scheme.count == 2
				&& scheme.items[0].part == PART_TEXT && !scheme.items[0].uses_username
				&& !scheme.items[0].uses_clientid, "a word that is not a factor is literal text");
		cong_scheme_free(&scheme);
		EXPECT(!cong_scheme_parse("salt+salt+salt+salt+salt+salt+salt+salt+salt", &scheme), "one factor past the limit");
		/* count is cleared before parsing, so a refused scheme cannot leave a
		 * usable-looking list behind. */
		EXPECT(scheme.count == 0, "a rejected scheme must not report factors");
		cong_scheme_free(&scheme);

		/* A segment that is not one of the three words is a template over the
		 * capture groups, and the plus is the separator - so the separator between
		 * two halves of a name is any other character. */
		EXPECT(cong_scheme_parse("%u1_%u2+salt", &scheme) && scheme.count == 2
				&& scheme.items[0].part == PART_TEXT && scheme.items[0].username_group == 2
				&& scheme.items[0].clientid_group == 0 && scheme.items[0].uses_username
				&& !scheme.items[0].uses_clientid && scheme.items[1].part == PART_SALT,
				"a template segment records the groups it reaches");
		EXPECT(scheme.items[0].text && !strcmp(scheme.items[0].text, "%u1_%u2"),
				"the segment is kept as written, got \"%s\"", scheme.items[0].text);
		{
			struct cong_scheme_use use;
			cong_scheme_usage(&scheme, &use);
			EXPECT(use.username && !use.clientid && use.salt
					&& use.username_groups == 2 && use.clientid_groups == 0,
					"usage says username group 2 plus salt");
		}
		cong_scheme_free(&scheme);

		EXPECT(cong_scheme_parse("%c2+%c1+salt", &scheme) && scheme.count == 3
				&& scheme.items[0].clientid_group == 2 && scheme.items[0].username_group == 0
				&& scheme.items[1].clientid_group == 1, "two template segments keep their own groups");
		cong_scheme_free(&scheme);

		/* "%%" is a percent, so nothing after it is a token. */
		EXPECT(cong_scheme_parse("%%u1+salt", &scheme) && scheme.count == 2
				&& scheme.items[0].part == PART_TEXT && !scheme.items[0].uses_username,
				"%% escapes the percent");
		cong_scheme_free(&scheme);

		/* A literal segment with no token is legal - it is a constant in the
		 * pre-image - but a bare percent form is not, because guessing which
		 * identity "%1" means would put a different password on the device. */
		EXPECT(cong_scheme_parse("device+salt", &scheme) && scheme.count == 2
				&& scheme.items[0].part == PART_TEXT && !scheme.items[0].uses_username,
				"a plain word is literal text");
		cong_scheme_free(&scheme);
		EXPECT(!cong_scheme_parse("%u+salt", &scheme), "%%u with no group number");
		EXPECT(scheme.count == 0, "a rejected template must not report segments");
		EXPECT(!cong_scheme_parse("%u0+salt", &scheme), "group 0 is spelled username");
		EXPECT(!cong_scheme_parse("%c0+salt", &scheme), "group 0 is spelled clientid");
		EXPECT(!cong_scheme_parse("%1+salt", &scheme), "a group needs its source letter");
		EXPECT(!cong_scheme_parse("%x1+salt", &scheme), "unknown escape");
		EXPECT(!cong_scheme_parse("50%+salt", &scheme), "a percent needs a token after it");
		/* A group number is one digit, both here and in a rule topic, so "%u10" is
		 * group 1 followed by a literal zero rather than a nonexistent group 10 -
		 * and the capture limit means no pattern can have a group 10 anyway. */
		EXPECT(cong_scheme_parse("%u10+salt", &scheme) && scheme.count == 2
				&& scheme.items[0].username_group == 1, "the digit after a group is literal text");
		cong_scheme_free(&scheme);
		/* Many references still fit inside one segment: it is the segment count
		 * that is capped, and a ninth segment is a typo. Refusing that one also
		 * exercises the free path, because eight of them own text by then. */
		EXPECT(cong_scheme_parse("%u1%u2%u3%u4%u5%u6%u7%u8+salt", &scheme) && scheme.count == 2
				&& scheme.items[0].username_group == 8, "eight references in one segment");
		cong_scheme_free(&scheme);
		EXPECT(!cong_scheme_parse("%u1+%u1+%u1+%u1+%u1+%u1+%u1+%u1+%u1", &scheme),
				"a ninth segment is past the limit");
	}
}

static bool scheme_text_is(struct cong_scheme *scheme, unsigned index, bool sanitize,
		const struct cong_groups *user, const struct cong_groups *client, const char *expected)
{
	char *out = NULL;
	size_t len = 0;
	bool ok;

	if(!cong_scheme_text_build(&scheme->items[index], sanitize, user, client, &out, &len)){
		return false;
	}
	/* The length is what enters the digest, so a test that only compared strings
	 * would miss an embedded NUL; check both, and the terminator besides. */
	ok = strlen(expected) == len && out[len] == '\0' && !memcmp(out, expected, len);
	free(out);
	return ok;
}

static void test_scheme_text(void)
{
	/* Group 0 is the whole match and is never addressed by a scheme, so index 0
	 * stays empty here exactly as it does after a real regexec(). */
	static struct cong_groups dashed_user = {2, { {NULL, 0}, {"ab-cd", 5}, {"de1", 3} }};
	static struct cong_groups partial_user = {2, { {NULL, 0}, {"ab-cd", 5}, {NULL, 0} }};
	static struct cong_groups gw_client = {2, { {NULL, 0}, {"AAAA", 4}, {"1234", 4} }};
	struct cong_scheme scheme;

	printf("scheme text build\n");

	/* Cleaning applies to each captured half, never to the literal separator - if
	 * it did, a scheme writing "_" between the halves would delete its own
	 * punctuation and the two halves would run together again. */
	EXPECT(cong_scheme_parse("%u1_%u2", &scheme) && scheme.count == 1, "one template segment");
	EXPECT(scheme_text_is(&scheme, 0, true, &dashed_user, NULL, "abcd_de1"),
			"sanitize cleans each group on its own");
	EXPECT(scheme_text_is(&scheme, 0, false, &dashed_user, NULL, "ab-cd_de1"),
			"sanitize off keeps the groups verbatim");
	cong_scheme_free(&scheme);

	/* An optional group that did not take part in the match joins as nothing,
	 * which is what makes "tag_abc" and "tag_abc_7" one rule instead of two. */
	EXPECT(cong_scheme_parse("%u1.%u2", &scheme) && scheme.count == 1, "parse optional");
	EXPECT(scheme_text_is(&scheme, 0, true, &partial_user, NULL, "abcd."),
			"a group that did not participate is the empty string");
	/* Beyond the groups the pattern has, there is likewise nothing to take. */
	EXPECT(cong_scheme_parse("%u1%u5", &scheme) && scheme.count == 1, "parse past");
	EXPECT(scheme_text_is(&scheme, 0, true, &dashed_user, NULL, "abcd"),
			"a group the table does not carry is also empty");
	cong_scheme_free(&scheme);

	/* "%%" is a percent and ends the token, so the "u1" after it is literal text
	 * and only the trailing "%u2" is a reference. */
	EXPECT(cong_scheme_parse("%%u1%u2", &scheme) && scheme.count == 1
			&& scheme.items[0].username_group == 2, "an escaped percent is not a reference");
	EXPECT(scheme_text_is(&scheme, 0, true, &dashed_user, NULL, "%u1de1"),
			"the escaped percent prints as itself, the rest as written");
	cong_scheme_free(&scheme);

	/* Clientid groups, a literal percent between them, and the two tables apart:
	 * %c1 must never read the username's captures. */
	EXPECT(cong_scheme_parse("%c1%%%c2", &scheme) && scheme.count == 1
			&& scheme.items[0].uses_clientid && !scheme.items[0].uses_username, "clientid template");
	EXPECT(scheme_text_is(&scheme, 0, true, NULL, &gw_client, "AAAA%1234"),
			"clientid groups and a literal percent");
	cong_scheme_free(&scheme);

	/* A segment with no token at all is a constant in the pre-image. */
	EXPECT(cong_scheme_parse("device", &scheme) && scheme.count == 1
			&& !scheme.items[0].uses_username && !scheme.items[0].uses_clientid, "literal segment");
	EXPECT(scheme_text_is(&scheme, 0, true, NULL, NULL, "device"), "literal text is never cleaned");
	EXPECT(scheme_text_is(&scheme, 0, false, NULL, NULL, "device"), "and not cleaned when off either");
	cong_scheme_free(&scheme);

	/* A keyword segment is not a template, so the renderer refuses it - the auth
	 * layer digests those from the identity itself. */
	EXPECT(cong_scheme_parse("salt", &scheme) && scheme.count == 1, "keyword segment");
	{
		char *out = NULL;
		size_t len = 0;
		EXPECT(!cong_scheme_text_build(&scheme.items[0], true, NULL, NULL, &out, &len),
				"a keyword is not rendered as text");
		EXPECT(out == NULL && len == 0, "and nothing is handed back");
	}
	cong_scheme_free(&scheme);
}

static void test_auth(void)
{
	struct cong_auth_table *table;
	unsigned lineno = 0;
	enum cong_decision decision;

	printf("auth\n");
	write_rules("test_auth.jsonl", AUTH_RULES);
	table = cong_auth_load("test_auth.jsonl");
	remove("test_auth.jsonl");
	if(!table){
		printf("  FAIL: the sample auth rules did not load\n");
		failures++;
		return;
	}
	EXPECT(table->rule_count == 9, "expected 9 rules, got %zu", table->rule_count);
	EXPECT(table->regex_count == 7, "expected 7 regex rules, got %zu", table->regex_count);

	decision = cong_auth_check(table, "dashboard", "any-client", "203.0.113.7",
			"c45c09aa5760a3562c35b01e8b6351b79bde1d51c3af408ddc92c9523328b9de", 64, &lineno);
	EXPECT(decision == CONG_ALLOW, "dashboard digest should authenticate, decision=%d", decision);
	EXPECT(lineno == 2, "rule line should be 2, got %u", lineno);

	decision = cong_auth_check(table, "dashboard", "c", "203.0.113.7",
			"C45C09AA5760A3562C35B01E8B6351B79BDE1D51C3AF408DDC92C9523328B9DE", 64, &lineno);
	EXPECT(decision == CONG_ALLOW, "hex comparison is case insensitive");

	decision = cong_auth_check(table, "dashboard", "c", "203.0.113.7",
			"0000000000000000000000000000000000000000000000000000000000000000", 64, &lineno);
	EXPECT(decision == CONG_DENY, "wrong digest must be DENY, got %d", decision);

	/* the regex rule digests the username with the underscore removed */
	decision = cong_auth_check(table, "aaaa_bbbb", "c", "203.0.113.7", "67b1d9a71df8f6b6aaf0a6e0a99e58eb", 32, &lineno);
	EXPECT(decision == CONG_ALLOW, "aaaa_bbbb should pass, decision=%d", decision);
	decision = cong_auth_check(table, "aaaa_cccc", "c", "203.0.113.7", "67b1d9a71df8f6b6aaf0a6e0a99e58eb", 32, &lineno);
	EXPECT(decision == CONG_DENY, "aaaa_cccc has a different digest, must not reuse aaaa_bbbb's");

	decision = cong_auth_check(table, "aaaa_BBBB", "c", "203.0.113.7", "67b1d9a71df8f6b6aaf0a6e0a99e58eb", 32, &lineno);
	EXPECT(decision == CONG_NO_MATCH, "regex is case sensitive, so no rule applies");

	decision = cong_auth_check(table, "no_such_user", "c", "203.0.113.7", "67b1d9a71df8f6b6aaf0a6e0a99e58eb", 32, &lineno);
	EXPECT(decision == CONG_NO_MATCH, "unknown username must be NO_MATCH, got %d", decision);

	/* clientid and ip are extra constraints on the same rule. The username is
	 * spelled "gw_01!" on purpose: it still matches "^gw_.*" and still cleans to
	 * "gw01" (so the digest below is unchanged), but the generic split rule of
	 * line 15 cannot claim it, so these two refusals stay the "no rule applies at
	 * all" answer they are testing for instead of "a rule applies and its
	 * password is wrong". */
	decision = cong_auth_check(table, "gw_01!", "gw-DEADBEEF", "10.1.2.3",
			"9f2cf6d121fc7f8a1d927ad3235673095d8386bb10c1a414c167f96ee4cd4cb7"
			"7e58a7f40be4830ce70834a6ba490bbb2dcbed2a2192e909f285a66a64802916", 128, &lineno);
	EXPECT(decision == CONG_ALLOW, "gw_01! with the right clientid and source should pass, decision=%d", decision);

	decision = cong_auth_check(table, "gw_01!", "other-client", "10.1.2.3",
			"9f2cf6d121fc7f8a1d927ad3235673095d8386bb10c1a414c167f96ee4cd4cb7"
			"7e58a7f40be4830ce70834a6ba490bbb2dcbed2a2192e909f285a66a64802916", 128, &lineno);
	EXPECT(decision == CONG_NO_MATCH, "clientid constraint must apply even when the digest is right");

	decision = cong_auth_check(table, "gw_01!", "gw-DEADBEEF", "192.168.1.5",
			"9f2cf6d121fc7f8a1d927ad3235673095d8386bb10c1a414c167f96ee4cd4cb7"
			"7e58a7f40be4830ce70834a6ba490bbb2dcbed2a2192e909f285a66a64802916", 128, &lineno);
	EXPECT(decision == CONG_NO_MATCH, "source outside 10.0.0.0/8 must not match");

	/* sanitize off keeps the underscore */
	decision = cong_auth_check(table, "legacy_x", "c", "203.0.113.7", "3f7a5dbd0e6174171dc78456b90ed7b0793e1410", 40, &lineno);
	EXPECT(decision == CONG_ALLOW, "legacy_x with sanitize=false should pass, decision=%d", decision);

	/* username+clientid+salt: the clientid is part of the secret, so one account
	 * cannot lend its digest to another device. */
	decision = cong_auth_check(table, "pump_0007", "PUMP-0007", "203.0.113.7",
			"e260f5e0e3ef64677147888d16deb018fc69c67aa008607d62e0e87ed0f064da", 64, &lineno);
	EXPECT(decision == CONG_ALLOW, "pump_0007 should pass, decision=%d", decision);
	EXPECT(lineno == 10, "rule line should be 10, got %u", lineno);

	decision = cong_auth_check(table, "pump_0007", "PUMP-9999", "203.0.113.7",
			"e260f5e0e3ef64677147888d16deb018fc69c67aa008607d62e0e87ed0f064da", 64, &lineno);
	EXPECT(decision == CONG_DENY, "a different clientid has a different digest, got %d", decision);

	/* The one sanitize switch covers both identities, so the dashed and the plain
	 * form of a clientid are the same account. */
	decision = cong_auth_check(table, "pump_0007", "PUMP0007", "203.0.113.7",
			"e260f5e0e3ef64677147888d16deb018fc69c67aa008607d62e0e87ed0f064da", 64, &lineno);
	EXPECT(decision == CONG_ALLOW, "PUMP0007 cleans to the same bytes, decision=%d", decision);

	/* A client that sends no clientid cannot satisfy a scheme that digests one.
	 * The rule is skipped instead of digested with "", and because the username
	 * did select that rule the answer is DENY rather than NO_MATCH. */
	decision = cong_auth_check(table, "pump_0007", "", "203.0.113.7",
			"e260f5e0e3ef64677147888d16deb018fc69c67aa008607d62e0e87ed0f064da", 64, &lineno);
	EXPECT(decision == CONG_DENY, "an empty clientid must not be digested, got %d", decision);
	decision = cong_auth_check(table, "pump_0007", NULL, "203.0.113.7",
			"e260f5e0e3ef64677147888d16deb018fc69c67aa008607d62e0e87ed0f064da", 64, &lineno);
	EXPECT(decision == CONG_DENY, "a missing clientid must not be digested either");

	/* clientid+salt: the username is not part of the secret, so it is still only a
	 * constraint here - which is why such a rule wants a clientid pattern. */
	decision = cong_auth_check(table, "whoever", "PUMP-0007", "203.0.113.7",
			"982a8647c5a8ef9b6c63c0ae45704e21a003d623ae8435db72855f2a56682127", 64, &lineno);
	EXPECT(decision == CONG_ALLOW, "clientid+salt should pass without the username, decision=%d", decision);
	EXPECT(lineno == 12, "rule line should be 12, got %u", lineno);

	decision = cong_auth_check(table, NULL, "PUMP-0007", "203.0.113.7",
			"982a8647c5a8ef9b6c63c0ae45704e21a003d623ae8435db72855f2a56682127", 64, &lineno);
	EXPECT(decision == CONG_ALLOW, "a scheme that ignores username does not need one, decision=%d", decision);

	/* Without a username no regex rule can even be selected, so the only
	 * candidate is the clientid-only rule - and this is the other scheme's
	 * digest, which is why the answer is DENY and not NO_MATCH. */
	decision = cong_auth_check(table, NULL, "PUMP-0007", "203.0.113.7",
			"e260f5e0e3ef64677147888d16deb018fc69c67aa008607d62e0e87ed0f064da", 64, &lineno);
	EXPECT(decision == CONG_DENY, "no rule can verify that digest, got %d", decision);

	/* split: the underscore between the two halves is literal text written by the
	 * scheme, and each half comes from the username's own capture groups. */
	decision = cong_auth_check(table, "abcde_device1", "c", "203.0.113.7",
			"48282547c287b53788604b2067d5f3230891196af4471bb7d7507047f6d4c0c0", 64, &lineno);
	EXPECT(decision == CONG_ALLOW, "abcde_device1 should pass on its two halves, decision=%d", decision);
	EXPECT(lineno == 15, "rule line should be 15, got %u", lineno);

	/* Whole-name digesting gives "abcde_device1" and "abcd_edevice1" the same
	 * password (9b54bb...), because both clean to "abcdedevice1". Digesting the
	 * halves instead is what separates them. */
	decision = cong_auth_check(table, "abcd_edevice1", "c", "203.0.113.7",
			"48282547c287b53788604b2067d5f3230891196af4471bb7d7507047f6d4c0c0", 64, &lineno);
	EXPECT(decision == CONG_DENY, "the neighbouring name must not reuse this digest, got %d", decision);
	decision = cong_auth_check(table, "abcd_edevice1", "c", "203.0.113.7",
			"81cfe26ffa043cc7b3a2d6722d590600a01be76c47c1f9b9dc9c87d5415ce6c3", 64, &lineno);
	EXPECT(decision == CONG_ALLOW, "abcd_edevice1 has a digest of its own, decision=%d", decision);

	/* Cleaning still applies, group by group: the dash inside the first half
	 * disappears, the separator the scheme wrote stays. */
	decision = cong_auth_check(table, "ab-cd_de1", "c", "203.0.113.7",
			"cc8c18d76c6883bec1d199742821a64ef46352cc3beb1f1d9b96f73735c11c14", 64, &lineno);
	EXPECT(decision == CONG_ALLOW, "ab-cd_de1 should pass with its first half cleaned, decision=%d", decision);

	/* A group scheme needs the username on the wire like any other scheme that
	 * names it: no username means no halves to digest, and the rule never becomes
	 * a candidate rather than digesting an empty group. */
	decision = cong_auth_check(table, NULL, "c", "203.0.113.7",
			"48282547c287b53788604b2067d5f3230891196af4471bb7d7507047f6d4c0c0", 64, &lineno);
	EXPECT(decision == CONG_NO_MATCH, "no username means no candidate for a group scheme, got %d", decision);

	/* The optional second group joins as the empty string, so "tag_abc" and
	 * "tag_abc_7" are one rule and two passwords instead of two rules. */
	decision = cong_auth_check(table, "tag_abc_7", "c", "203.0.113.7", "7e60771fa5b5e918a61c6be2495b0031", 32, &lineno);
	EXPECT(decision == CONG_ALLOW, "tag_abc_7 should pass, decision=%d", decision);
	EXPECT(lineno == 17, "rule line should be 17, got %u", lineno);
	decision = cong_auth_check(table, "tag_abc", "c", "203.0.113.7", "f92e937bbb34132cf0c5b4b6e0b79beb", 32, &lineno);
	EXPECT(decision == CONG_ALLOW, "a group that did not participate joins as nothing, decision=%d", decision);

	/* clientid groups, and the order of the segments is the order of the digest:
	 * %c2+%c1 puts the second half first, so the halves cannot be swapped by
	 * accident and still log in. */
	decision = cong_auth_check(table, "whoever", "GW-AAAA-1234", "203.0.113.7",
			"91423e38311e92eec2e046ef5177a1d79da3a93fe1b9a77db43f1975c12d0e90", 64, &lineno);
	EXPECT(decision == CONG_ALLOW, "GW-AAAA-1234 in reverse order should pass, decision=%d", decision);
	EXPECT(lineno == 19, "rule line should be 19, got %u", lineno);
	decision = cong_auth_check(table, NULL, "GW-AAAA-1234", "203.0.113.7",
			"91423e38311e92eec2e046ef5177a1d79da3a93fe1b9a77db43f1975c12d0e90", 64, &lineno);
	EXPECT(decision == CONG_ALLOW, "a clientid group scheme needs no username, decision=%d", decision);
	decision = cong_auth_check(table, "whoever", "GW-1234-AAAA", "203.0.113.7",
			"91423e38311e92eec2e046ef5177a1d79da3a93fe1b9a77db43f1975c12d0e90", 64, &lineno);
	EXPECT(decision == CONG_DENY, "swapping the halves is a different password, got %d", decision);
	decision = cong_auth_check(table, "whoever", "GW-1234-AAAA", "203.0.113.7",
			"93bf18e20a13c9763d8dcfd4a1c78f2f80e1ec86cefa474b80e01c9c5bcd189f", 64, &lineno);
	EXPECT(decision == CONG_ALLOW, "GW-1234-AAAA has its own digest, decision=%d", decision);

	/* a password that is not a hex digest at all */
	decision = cong_auth_check(table, "dashboard", "c", "203.0.113.7", "hunter2", 7, &lineno);
	EXPECT(decision == CONG_DENY, "non hex password must be DENY");
	decision = cong_auth_check(table, "dashboard", "c", "203.0.113.7", NULL, 0, &lineno);
	EXPECT(decision == CONG_NO_MATCH, "empty password must be NO_MATCH");

	cong_auth_free(table);

	write_rules("test_bad.jsonl", BAD_KEY_RULES);
	table = cong_auth_load("test_bad.jsonl");
	remove("test_bad.jsonl");
	EXPECT(table == NULL, "an unknown key must refuse the whole file");
	if(table){
		cong_auth_free(table);
	}

	/* Duplicate keys are legal JSON, but the plugin reads the first occurrence and
	 * an ordinary parser keeps the last, so the rule that loads would not be the
	 * rule that was checked. Refusing the file is the only answer both sides agree
	 * on. */
	EXPECT(auth_refuses("{\"username\":\"dashboard\",\"username\":\"other\",\"salt\":\"s\",\"alg\":\"sha256\",\"scheme\":\"username+salt\"}\n"),
			"a duplicated key must refuse the whole file");
	EXPECT(auth_refuses("{\"username\":\"dashboard\",\"salt\":\"s\",\"salt\":\"t\",\"alg\":\"sha256\",\"scheme\":\"username+salt\"}\n"),
			"a duplicated salt refuses it too, even when the two values agree");

	/* A scheme may name the same factor more than once. The repeat does not change
	 * the pre-image, and the second mention has to reuse the value prepared for the
	 * first instead of allocating another one - this is the case that leaked a
	 * buffer per login attempt, so it has to be exercised under the sanitizer. */
	write_rules("test_repeat.jsonl", "{\"username\":\"ab_cd\",\"salt\":\"s\",\"alg\":\"sha256\",\"scheme\":\"username+salt+username+clientid\"}\n");
	table = cong_auth_load("test_repeat.jsonl");
	remove("test_repeat.jsonl");
	if(table){
		/* sha256("abcd" + "s" + "abcd" + "c"), with both spellings of the username
		 * sanitized the same way the first one is. */
		decision = cong_auth_check(table, "ab_cd", "c", "127.0.0.1",
				"96fb9122ec36fede3aaab77c32dd6c67917235eb3d3b548f5eb03092728994e2", 64, &lineno);
		EXPECT(decision == CONG_ALLOW, "a repeated factor digests the same value again");
		decision = cong_auth_check(table, "ab_cd", "c", "127.0.0.1",
				"605fdf2a49345f0728d0f967cc2bef97dcdb922e54137564959aa14a31b67f53", 64, &lineno);
		EXPECT(decision == CONG_DENY, "and the same password is still checked, not skipped");
		cong_auth_free(table);
	} else {
		EXPECT(false, "a scheme with a repeated factor must load");
	}
	/* The unsanitized pre-image must not verify: the repeat cannot become a way to
	 * bypass the cleaning step. */
	EXPECT(!auth_refuses("{\"username\":\"ab_cd\",\"salt\":\"s\",\"alg\":\"sha256\",\"scheme\":\"clientid+username+username+salt\"}\n"),
			"a repeat in another position loads as well");

	/* A %uN reference is a promise about the username pattern of the same rule,
	 * and %cN about the clientid pattern. A file that does not keep the promise
	 * would put a password on the device that no connection can ever reproduce,
	 * so the load stops rather than digesting a group that is not there. */
	EXPECT(auth_refuses("{\"username\":\"dashboard\",\"salt\":\"s\",\"alg\":\"sha256\",\"scheme\":\"%u1+salt\"}\n"),
			"a literal username has no groups to reference");
	EXPECT(auth_refuses("{\"username\":\"^ab_([a-z]+)$\",\"match\":\"regex\",\"salt\":\"s\",\"alg\":\"sha256\",\"scheme\":\"%u2+salt\"}\n"),
			"group 2 does not exist in that pattern");
	EXPECT(auth_refuses("{\"clientid\":\"^GW-([0-9A-F]{4})$\",\"clientid_match\":\"regex\",\"salt\":\"s\",\"alg\":\"sha256\",\"scheme\":\"%c2+salt\"}\n"),
			"a clientid group needs the clientid pattern to carry it");
	EXPECT(!auth_refuses("{\"username\":\"^ab_([a-z]+)$\",\"match\":\"regex\",\"salt\":\"s\",\"alg\":\"sha256\",\"scheme\":\"%u1+salt\"}\n"),
			"a pattern that keeps its promise loads");
	/* "usernamee" parses as a constant, not as the username, and the loader only
	 * warns about it: a refusal would be wrong for the operator who did mean the
	 * literal text, and the digest fails closed either way. The warning has to
	 * fire for a tail of letters too, not just for "salt_x" with its underscore,
	 * because a mistyped factor is usually spelled like that. */
	EXPECT(!auth_refuses("{\"username\":\"x\",\"salt\":\"s\",\"alg\":\"sha256\",\"scheme\":\"username+usernamee\"}\n"),
			"a factor-shaped literal segment warns but loads");
	/* An unknown percent form is not a token the digest can guess, and the limit
	 * is on segments, so nine of them is a typo. */
	EXPECT(auth_refuses("{\"username\":\"x\",\"salt\":\"s\",\"alg\":\"sha256\",\"scheme\":\"%user+salt\"}\n"),
			"a group number must follow %%u or %%c");
	EXPECT(auth_refuses("{\"username\":\"x\",\"salt\":\"s\",\"alg\":\"sha256\",\"scheme\":\"%1+salt\"}\n"),
			"a group reference must name its identity");
	EXPECT(auth_refuses("{\"username\":\"x\",\"salt\":\"s\",\"alg\":\"sha256\",\"scheme\":\"u1+u2+u3+u4+u5+u6+u7+u8+u9\"}\n"),
			"a ninth segment is past the limit");

	write_rules("test_empty.jsonl", EMPTY_RULES);
	table = cong_auth_load("test_empty.jsonl");
	remove("test_empty.jsonl");
	if(table){
		EXPECT(table->rule_count == 0, "empty file should load 0 rules");
		decision = cong_auth_check(table, "dashboard", "c", "127.0.0.1",
				"c45c09aa5760a3562c35b01e8b6351b79bde1d51c3af408ddc92c9523328b9de", 64, &lineno);
		EXPECT(decision == CONG_NO_MATCH, "an empty table can match nothing");
		cong_auth_free(table);
	}else{
		EXPECT(false, "a comment only file should still load");
	}

	table = cong_auth_load("does_not_exist.jsonl");
	EXPECT(table == NULL, "a missing file must fail to load");
}

static void test_acl(void)
{
	struct cong_acl_table *table;
	enum cong_decision decision;
	unsigned lineno = 0;

	printf("acl\n");
	write_rules("test_acl.jsonl", ACL_RULES);
	table = cong_acl_load("test_acl.jsonl");
	remove("test_acl.jsonl");
	if(!table){
		printf("  FAIL: the sample acl rules did not load\n");
		failures++;
		return;
	}
	EXPECT(table->rule_count == 8, "expected 8 rules, got %zu", table->rule_count);

	/* dashboard may subscribe to $SYS/# - and the subscription path must be the
	 * one asked about, since that is what the broker's own acl-file plugin
	 * refuses to check at all. */
	strcpy(last_op, "none");
	decision = cong_acl_check(table, &ops, CONG_ACL_SUBSCRIBE, "$SYS/#", "dashboard", "c1", "203.0.113.7", &lineno);
	EXPECT(decision == CONG_ALLOW, "dashboard subscribing $SYS/# should be allowed, decision=%d", decision);
	EXPECT(lineno == 1, "line 1, got %u", lineno);
	EXPECT(!strcmp(last_op, "subscribe"), "subscribe checks must use the subscription matcher, used %s", last_op);

	/* the subscription filter "#" against the acl "$SYS/#" is not covered by it,
	 * so dashboard falls through to the deny rule on line 3 */
	decision = cong_acl_check(table, &ops, CONG_ACL_SUBSCRIBE, "#", "dashboard", "c1", "203.0.113.7", &lineno);
	EXPECT(decision == CONG_DENY, "subscribing # should hit the deny rule, decision=%d", decision);
	EXPECT(lineno == 3, "line 3, got %u", lineno);

	/* the deny rule lists "#" and "+/#" as literal strings, so those only stop an
	 * actual wildcard subscription, never a real topic */
	decision = cong_acl_check(table, &ops, CONG_ACL_SUBSCRIBE, "sensor/#", "ops", "c1", "203.0.113.7", &lineno);
	EXPECT(decision == CONG_ALLOW, "sensor/# is not the literal +/# pattern, should reach the catch all");
	EXPECT(lineno == 8, "line 8, got %u", lineno);

	decision = cong_acl_check(table, &ops, CONG_ACL_SUBSCRIBE, "+/#", "ops", "c1", "203.0.113.7", &lineno);
	EXPECT(decision == CONG_DENY, "the literal +/# subscription must be denied");

	/* receiving a message is a READ check, which subscribe rules cover */
	decision = cong_acl_check(table, &ops, CONG_ACL_READ, "$SYS/broker/uptime", "dashboard", "c1", "203.0.113.7", &lineno);
	EXPECT(decision == CONG_ALLOW, "dashboard may receive $SYS messages, decision=%d", decision);
	decision = cong_acl_check(table, &ops, CONG_ACL_READ, "$SYS/broker/uptime", "ops", "c1", "203.0.113.7", &lineno);
	EXPECT(decision == CONG_DENY, "others may not receive $SYS messages");

	/* a $ topic is never matched by a non $ rule, which is what keeps "#" from
	 * leaking $SYS to the client on line 2 */
	decision = cong_acl_check(table, &ops, CONG_ACL_READ, "$SYS/broker/uptime", "ops", "c1", "127.0.0.1", &lineno);
	EXPECT(decision == CONG_ALLOW, "127.0.0.1 has an explicit $SYS/# rule");
	EXPECT(lineno == 2, "line 2, got %u", lineno);

	/* publishing goes through the plain topic matcher, not the subscription one */
	strcpy(last_op, "none");
	decision = cong_acl_check(table, &ops, CONG_ACL_WRITE, "sensor/x/data", "ops", "c1", "127.0.0.1", &lineno);
	EXPECT(decision == CONG_ALLOW, "the line 2 \"all\" rule covers publishing, decision=%d", decision);
	EXPECT(lineno == 2, "line 2, got %u", lineno);
	EXPECT(!strcmp(last_op, "topic"), "publish checks must use the topic matcher, used %s", last_op);

	/* a rule without \"topics\" covers every topic, and gets there without
	 * asking a matcher at all */
	strcpy(last_op, "none");
	decision = cong_acl_check(table, &ops, CONG_ACL_WRITE, "sensor/x/data", "ops", "c1", "203.0.113.7", &lineno);
	EXPECT(decision == CONG_ALLOW, "publish should reach the catch all, decision=%d", decision);
	EXPECT(lineno == 8, "line 8, got %u", lineno);
	EXPECT(!strcmp(last_op, "none"), "a catch all rule needs no topic matching, used %s", last_op);

	/* %c is expanded by the core layer and then handed to the plain topic
	 * matcher - the broker's own %c could never cross a level, ours can. */
	strcpy(last_op, "none");
	decision = cong_acl_check(table, &ops, CONG_ACL_WRITE, "sensor/dev-1/data", "aaaa_bbbb", "dev-1", "203.0.113.7", &lineno);
	EXPECT(decision == CONG_ALLOW, "device publishing its own branch should be allowed, decision=%d", decision);
	EXPECT(lineno == 4, "line 4, got %u", lineno);
	EXPECT(!strcmp(last_op, "topic"), "an expanded rule still uses the topic matcher, used %s", last_op);

	/* the device may not write another device's branch. The %c rule on line 4
	 * rejects it, and the sample file then lets it through on line 8 - that is a
	 * property of this catch-all, so production files end with {"effect":"deny"}. */
	decision = cong_acl_check(table, &ops, CONG_ACL_WRITE, "sensor/dev-2/data", "aaaa_bbbb", "dev-1", "203.0.113.7", &lineno);
	EXPECT(decision == CONG_ALLOW, "the catch all should be what decides, decision=%d", decision);
	EXPECT(lineno == 8, "another device's branch should fall through to line 8, got %u", lineno);

	/* username captures: abcde_aaaa and aaaa_abcde both land on the product
	 * first, device second */
	decision = cong_acl_check(table, &ops, CONG_ACL_WRITE, "abcde/aaaa/event", "abcde_aaaa", "c1", "203.0.113.7", &lineno);
	EXPECT(decision == CONG_ALLOW, "abcde_aaaa publishing abcde/aaaa/event, decision=%d", decision);
	EXPECT(lineno == 5, "line 5, got %u", lineno);
	decision = cong_acl_check(table, &ops, CONG_ACL_WRITE, "abcde/aaaa/event", "aaaa_abcde", "c1", "203.0.113.7", &lineno);
	EXPECT(decision == CONG_ALLOW, "aaaa_abcde publishing abcde/aaaa/event, decision=%d", decision);
	EXPECT(lineno == 6, "line 6, got %u", lineno);

	/* and it must not reach a sibling device's branch */
	decision = cong_acl_check(table, &ops, CONG_ACL_WRITE, "abcde/bbbb/event", "abcde_aaaa", "c1", "203.0.113.7", &lineno);
	EXPECT(decision == CONG_ALLOW, "only the catch all lets this through, decision=%d", decision);
	EXPECT(lineno == 8, "line 8, got %u", lineno);

	/* the device branch may subscribe its own subtree through a %1 rule */
	decision = cong_acl_check(table, &ops, CONG_ACL_SUBSCRIBE, "abcde/aaaa/event", "gw_aaaa", "c1", "203.0.113.7", &lineno);
	EXPECT(decision == CONG_ALLOW, "gw_aaaa subscribing its own branch, decision=%d", decision);
	EXPECT(lineno == 7, "line 7, got %u", lineno);
	decision = cong_acl_check(table, &ops, CONG_ACL_SUBSCRIBE, "abcde/bbbb/event", "gw_aaaa", "c1", "203.0.113.7", &lineno);
	EXPECT(decision == CONG_ALLOW, "again only the catch all, decision=%d", decision);
	EXPECT(lineno == 8, "line 8, got %u", lineno);

	/* an identity that carries wildcards must not be allowed to widen a rule:
	 * clientid "evil/#" expanded into "sensor/evil/#/data" would match anything
	 * under sensor/, so the expansion is refused and the request denied. */
	decision = cong_acl_check(table, &ops, CONG_ACL_WRITE, "sensor/anything/data", "aaaa_bbbb", "evil/#", "203.0.113.7", &lineno);
	EXPECT(decision == CONG_ERROR, "a wildcard in the identity must be an error, decision=%d", decision);

	/* empty table denies by falling through */
	cong_acl_free(table);
	write_rules("test_acl_empty.jsonl", EMPTY_RULES);
	table = cong_acl_load("test_acl_empty.jsonl");
	remove("test_acl_empty.jsonl");
	if(table){
		decision = cong_acl_check(table, &ops, CONG_ACL_WRITE, "a/b", "u", "c", "127.0.0.1", &lineno);
		EXPECT(decision == CONG_NO_MATCH, "an empty acl table can match nothing");
		cong_acl_free(table);
	}else{
		EXPECT(false, "an empty acl file should still load");
	}
}

static void test_expand(void)
{
	char big[300];
	char out[128];
	struct cong_subject subject;
	struct cong_groups groups;

	printf("expand\n");

	EXPECT(cong_topic_expand(out, sizeof(out), "%c/%u", "dev-1", "abcde_aaaa", NULL) == CONG_EXPAND_OK, "identity tokens");
	EXPECT(!strcmp(out, "dev-1/abcde_aaaa"), "got \"%s\"", out);

	/* this is the case the broker's own %c could not do: one identity, two levels */
	EXPECT(cong_topic_expand(out, sizeof(out), "%c/event", "abcde/aaaa", NULL, NULL) == CONG_EXPAND_OK, "cross level %%c");
	EXPECT(!strcmp(out, "abcde/aaaa/event"), "got \"%s\"", out);

	/* a wildcard reaching the matcher through an identity would widen the rule */
	EXPECT(cong_topic_expand(out, sizeof(out), "sensor/%c/data", "evil/#", "u", NULL) == CONG_EXPAND_WILDCARD, "clientid with #");
	EXPECT(cong_topic_expand(out, sizeof(out), "sensor/%u/data", "c", "ev+il", NULL) == CONG_EXPAND_WILDCARD, "username with +");

	/* an absent identity matches nothing rather than an empty level */
	EXPECT(cong_topic_expand(out, sizeof(out), "x/%u", "c", NULL, NULL) == CONG_EXPAND_NO_MATCH, "NULL username");
	EXPECT(cong_topic_expand(out, sizeof(out), "x/%c", "", "u", NULL) == CONG_EXPAND_NO_MATCH, "empty clientid");

	/* %% is a literal percent, and a percent that starts no token stays verbatim */
	EXPECT(cong_topic_expand(out, sizeof(out), "sales/50%%off", "c", "u", NULL) == CONG_EXPAND_OK, "%% escape");
	EXPECT(!strcmp(out, "sales/50%off"), "got \"%s\"", out);
	EXPECT(cong_topic_expand(out, sizeof(out), "sales/50%off", "c", "u", NULL) == CONG_EXPAND_OK, "unknown token");
	EXPECT(!strcmp(out, "sales/50%off"), "got \"%s\"", out);

	/* refusing to truncate is the point of TOOLONG */
	memset(big, 'x', sizeof(big) - 1);
	big[sizeof(big) - 1] = '\0';
	EXPECT(cong_topic_expand(out, sizeof(out), "a/%u", "c", big, NULL) == CONG_EXPAND_TOOLONG, "overflow must be refused");

	EXPECT(cong_topic_expand(out, sizeof(out), "abcde/%1/event", "c", "u", NULL) == CONG_EXPAND_NO_CAPTURES, "%%1 without captures");

	EXPECT(cong_subject_compile(&subject, "^abcde_([a-z0-9]+)$", "regex", true, "user", "test", 1), "compile grouped regex");
	EXPECT(subject.grouped && subject.ngroups == 1, "one capture expected, got grouped=%d ngroups=%d", (int) subject.grouped, subject.ngroups);
	EXPECT(cong_subject_match_groups(&subject, "abcde_aaaa", &groups), "match with groups");
	EXPECT(groups.count == 1, "count");
	EXPECT(groups.g[1].len == 4 && !memcmp(groups.g[1].text, "aaaa", 4), "group 1");
	/* group 0 is the whole match, which is handy for "%0" style audit topics */
	EXPECT(groups.g[0].len == 10 && !memcmp(groups.g[0].text, "abcde_aaaa", 10), "group 0");
	EXPECT(cong_topic_expand(out, sizeof(out), "%1/%0", "c", "u", &groups) == CONG_EXPAND_OK, "group expansion");
	EXPECT(!strcmp(out, "aaaa/abcde_aaaa"), "got \"%s\"", out);
	EXPECT(!cong_subject_match_groups(&subject, "zzz", &groups), "non matching value has no groups");
	cong_subject_free(&subject);

	/* without want_groups there are no captures to hand back */
	EXPECT(cong_subject_compile(&subject, "^abcde_([a-z0-9]+)$", "regex", false, "user", "test", 1), "compile plain regex");
	EXPECT(!subject.grouped, "should not be grouped");
	EXPECT(!cong_subject_match_groups(&subject, "abcde_aaaa", &groups), "no captures available");
	EXPECT(cong_subject_match(&subject, "abcde_aaaa"), "plain matching still works");
	cong_subject_free(&subject);

	/* ten groups is one too many for %1..%9 plus the whole match */
	EXPECT(!cong_subject_compile(&subject, "^(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)$", "regex", true, "user", "test", 1), "too many groups");
}

/* ------------------------------------------------------ topic matchers (real) */

/* The two functions the shipping plugin passes to the ACL layer. Expectations
 * below were read off mosquitto 2.1.2's own topic_matches_sub()/sub_matches_acl()
 * (the Mosquitto-side repo re-derives that against both source trees with its
 * make diffcheck), so this section is a regression net for the port, not a
 * second opinion on it. */
static const struct cong_topic_ops real_ops = {
	cong_topic_matches_sub, cong_sub_matches_acl
};

static void expect_topic(const char *pattern, const char *topic, int want_rc, bool want_match)
{
	bool got = !want_match;
	int rc = cong_topic_matches_sub(pattern, topic, &got);

	EXPECT(rc == want_rc && got == want_match,
			"publish rule \"%s\" vs topic \"%s\": got (rc %d, %s), want (rc %d, %s)",
			pattern, topic, rc, got ? "match" : "no", want_rc, want_match ? "match" : "no");
}

static void expect_cover(const char *pattern, const char *sub, int want_rc, bool want_match)
{
	bool got = !want_match;
	int rc = cong_sub_matches_acl(pattern, sub, &got);

	EXPECT(rc == want_rc && got == want_match,
			"publish rule \"%s\" vs subscription \"%s\": got (rc %d, %s), want (rc %d, %s)",
			pattern, sub, rc, got ? "match" : "no", want_rc, want_match ? "match" : "no");
}

static void test_topic_match(void)
{
	struct cong_acl_table *table;
	enum cong_decision decision;
	unsigned lineno = 0;

	printf("topic matching\n");

	/* One pattern, two questions. "#" covers its own parent level, and a publish
	 * topic may not carry wildcards at all while a subscription may. */
	expect_topic("sensor/#", "sensor", CONG_TOPIC_OK, true);
	expect_topic("sensor/#", "sensor/aaaa/data", CONG_TOPIC_OK, true);
	expect_topic("sensor/#", "sensor/#", CONG_TOPIC_EINVAL, false);
	expect_cover("sensor/#", "sensor/#", CONG_TOPIC_OK, true);

	/* A narrower rule does not cover a broader subscription. */
	expect_cover("sensor/+", "sensor/#", CONG_TOPIC_OK, false);
	expect_cover("sensor/+", "sensor/aaaa", CONG_TOPIC_OK, true);
	expect_topic("sensor/+", "sensor/aaaa/data", CONG_TOPIC_OK, false);

	/* "#" may select the empty level a trailing "+" consumed. */
	expect_topic("foo/+/#", "foo/bar", CONG_TOPIC_OK, true);
	expect_cover("foo/+/#", "foo/bar", CONG_TOPIC_OK, true);

	/* Wildcards that do not own their level are refused, not unmatched: a typo in
	 * a rule file has to be visible. */
	expect_topic("a/+b", "a/x", CONG_TOPIC_EINVAL, false);
	expect_topic("a#", "a", CONG_TOPIC_EINVAL, false);
	expect_cover("a#", "a", CONG_TOPIC_EINVAL, false);
	expect_topic("", "a", CONG_TOPIC_EINVAL, false);
	expect_topic("a", "", CONG_TOPIC_EINVAL, false);

	/* The $ hierarchy is not reachable from a pattern that does not start there,
	 * and a trailing slash is its own level. */
	expect_topic("#", "$SYS/broker/uptime", CONG_TOPIC_OK, false);
	expect_topic("$SYS/#", "$SYS/broker/uptime", CONG_TOPIC_OK, true);
	expect_cover("$SYS/#", "#", CONG_TOPIC_OK, false);
	expect_topic("a/b", "a/b/", CONG_TOPIC_OK, false);
	expect_topic("+/+", "a/b", CONG_TOPIC_OK, true);
	expect_topic("+", "a/b", CONG_TOPIC_OK, false);

	/* Through the ACL engine, so the refusal path is the one the plugin takes. */
	write_rules("test_real_ops.jsonl",
			"{\"effect\":\"allow\",\"user\":\"dev\",\"action\":\"subscribe\",\"topics\":[\"abcde/#\"]}\n"
			"{\"effect\":\"allow\",\"user\":\"dev\",\"action\":\"publish\",\"topics\":[\"abcde/%c/data\"]}\n");
	table = cong_acl_load("test_real_ops.jsonl");
	remove("test_real_ops.jsonl");
	if(table){
		decision = cong_acl_check(table, &real_ops, CONG_ACL_SUBSCRIBE, "abcde/#", "dev", "abcde_aaaa", "127.0.0.1", &lineno);
		EXPECT(decision == CONG_ALLOW, "a subscription as broad as the rule is covered, decision=%d", decision);
		decision = cong_acl_check(table, &real_ops, CONG_ACL_SUBSCRIBE, "abcde/aaaa/data", "dev", "c", "127.0.0.1", &lineno);
		EXPECT(decision == CONG_ALLOW, "a concrete topic under the rule, decision=%d", decision);
		decision = cong_acl_check(table, &real_ops, CONG_ACL_WRITE, "abcde/#", "dev", "c", "127.0.0.1", &lineno);
		EXPECT(decision == CONG_ERROR, "a publish carrying wildcards is refused, decision=%d", decision);
		decision = cong_acl_check(table, &real_ops, CONG_ACL_WRITE, "abcde/c/data", "dev", "c", "127.0.0.1", &lineno);
		EXPECT(decision == CONG_ALLOW, "expanded %%c under the real matcher, decision=%d", decision);
		cong_acl_free(table);
	}else{
		EXPECT(false, "the real-ops rules should load");
	}
}

static void test_acl_templates(void)
{
	static const char *const pct_rules =
			"{\"effect\":\"allow\",\"user\":\"pct\",\"action\":\"publish\",\"topics\":[\"sales/50%%off\"]}\n";
	static const char *const eq_rules =
			"{\"effect\":\"allow\",\"user\":\"^abcde_([a-z0-9]+)$\",\"match\":\"regex\",\"action\":\"publish\",\"topics\":[{\"eq\":\"abcde/%1/event\"}]}\n";
	static const char *const no_regex_user =
			"{\"effect\":\"allow\",\"user\":\"abcde_aaaa\",\"action\":\"publish\",\"topics\":[\"abcde/%1/event\"]}\n";
	static const char *const missing_match =
			"{\"effect\":\"allow\",\"user\":\"^abcde_([a-z0-9]+)$\",\"action\":\"publish\",\"topics\":[\"abcde/%1/event\"]}\n";
	static const char *const group_overrun =
			"{\"effect\":\"allow\",\"user\":\"^abcde_([a-z0-9]+)$\",\"match\":\"regex\",\"action\":\"publish\",\"topics\":[\"abcde/%2/event\"]}\n";
	static const char *const eq_two_entries =
			"{\"effect\":\"deny\",\"action\":\"subscribe\",\"topics\":[\"$SYS/#\",{\"eq\":\"#\"},{\"eq\":\"+/#\"}]}\n";
	static const char *const eq_extra_key =
			"{\"effect\":\"allow\",\"user\":\"x\",\"action\":\"publish\",\"topics\":[{\"eq\":\"a/b\",\"effect\":\"deny\"}]}\n";
	struct cong_acl_table *table;
	enum cong_decision decision;
	unsigned lineno = 0;

	printf("acl templates\n");

	/* %% is rewritten even when nothing else needs expanding, so a topic that
	 * genuinely contains a percent stays writable. */
	write_rules("test_pct.jsonl", pct_rules);
	table = cong_acl_load("test_pct.jsonl");
	remove("test_pct.jsonl");
	if(table){
		decision = cong_acl_check(table, &ops, CONG_ACL_WRITE, "sales/50%off", "pct", "c", "127.0.0.1", &lineno);
		EXPECT(decision == CONG_ALLOW, "50%%off should match sales/50%%off, decision=%d", decision);
		cong_acl_free(table);
	}else{
		EXPECT(false, "the %% rule should load");
	}

	/* {eq} entries expand too, and then compare literally */
	write_rules("test_eq.jsonl", eq_rules);
	table = cong_acl_load("test_eq.jsonl");
	remove("test_eq.jsonl");
	if(table){
		decision = cong_acl_check(table, &ops, CONG_ACL_WRITE, "abcde/aaaa/event", "abcde_aaaa", "c", "127.0.0.1", &lineno);
		EXPECT(decision == CONG_ALLOW, "expanded {eq} should match, decision=%d", decision);
		decision = cong_acl_check(table, &ops, CONG_ACL_WRITE, "abcde/aaaa/#", "abcde_aaaa", "c", "127.0.0.1", &lineno);
		EXPECT(decision == CONG_NO_MATCH, "an {eq} entry is literal, and nothing else is left");
		cong_acl_free(table);
	}else{
		EXPECT(false, "the {eq} template rule should load");
	}

	/* all three ways of asking for a capture that cannot exist have to refuse
	 * the file: the loader cannot know what the operator meant. */
	write_rules("test_bad1.jsonl", no_regex_user);
	table = cong_acl_load("test_bad1.jsonl");
	remove("test_bad1.jsonl");
	EXPECT(table == NULL, "%%1 with a plain user must refuse the file");
	cong_acl_free(table);

	write_rules("test_bad2.jsonl", missing_match);
	table = cong_acl_load("test_bad2.jsonl");
	remove("test_bad2.jsonl");
	EXPECT(table == NULL, "%%1 without \"match\": \"regex\" must refuse the file");
	cong_acl_free(table);

	write_rules("test_bad3.jsonl", group_overrun);
	table = cong_acl_load("test_bad3.jsonl");
	remove("test_bad3.jsonl");
	EXPECT(table == NULL, "%%2 with a single group must refuse the file");
	cong_acl_free(table);

	/* the same guard on the acl side: "user" twice means two different rules were
	 * written into one line, and which one applies depends on the parser. */
	write_rules("test_dup_acl.jsonl", "{\"effect\":\"allow\",\"user\":\"a\",\"user\":\"b\",\"action\":\"publish\",\"topics\":[\"t\"]}\n");
	table = cong_acl_load("test_dup_acl.jsonl");
	remove("test_dup_acl.jsonl");
	EXPECT(table == NULL, "a duplicated key must refuse an acl rule too");
	cong_acl_free(table);

	/* "may only hold eq" is a promise about the object's own members, not about
	 * what follows it in the topics array. Reading the array link as a second key
	 * refused every rule that put a literal topic anywhere but last - which is how
	 * the shipped acl.jsonl writes its $SYS deny line. */
	write_rules("test_eq_order.jsonl", eq_two_entries);
	table = cong_acl_load("test_eq_order.jsonl");
	remove("test_eq_order.jsonl");
	EXPECT(table != NULL, "two {eq} entries in a row must load");
	if(table){
		decision = cong_acl_check(table, &ops, CONG_ACL_SUBSCRIBE, "#", "x", "c", "127.0.0.1", &lineno);
		EXPECT(decision == CONG_DENY, "the {eq} after the first one is still in the list, decision=%d", decision);
		cong_acl_free(table);
	}

	/* a real second key inside one entry is still refused */
	write_rules("test_eq_key.jsonl", eq_extra_key);
	table = cong_acl_load("test_eq_key.jsonl");
	remove("test_eq_key.jsonl");
	EXPECT(table == NULL, "an {eq} entry with a second key must refuse the file");
	cong_acl_free(table);
}

int main(void)
{
	printf("cong core unit tests\n\n");

	test_sanitize();
	test_hex();
	test_net();
	test_subject();
	test_digest_vectors();
	test_scheme_text();
	test_expand();
	test_topic_match();
	test_auth();
	test_acl();
	test_acl_templates();

	printf("\n%d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
