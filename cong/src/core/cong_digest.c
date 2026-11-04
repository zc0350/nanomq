#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "cong_core.h"

static const EVP_MD *alg_to_md(enum cong_alg alg)
{
	switch(alg){
		case CONG_ALG_MD5:
			return EVP_md5();
		case CONG_ALG_SHA1:
			return EVP_sha1();
		case CONG_ALG_SHA256:
			return EVP_sha256();
		case CONG_ALG_SHA512:
			return EVP_sha512();
	}
	return NULL;
}

bool cong_alg_parse(const char *text, enum cong_alg *alg)
{
	if(!strcmp(text, "md5")){
		*alg = CONG_ALG_MD5;
	}else if(!strcmp(text, "sha1")){
		*alg = CONG_ALG_SHA1;
	}else if(!strcmp(text, "sha256")){
		*alg = CONG_ALG_SHA256;
	}else if(!strcmp(text, "sha512")){
		*alg = CONG_ALG_SHA512;
	}else{
		return false;
	}
	return true;
}

/* Lengths are hard coded rather than read from EVP_MD_get_size() so the same
 * source builds without deprecation warnings on both OpenSSL 1.1 and 3.x. */
size_t cong_alg_digest_len(enum cong_alg alg)
{
	switch(alg){
		case CONG_ALG_MD5:
			return 16;
		case CONG_ALG_SHA1:
			return 20;
		case CONG_ALG_SHA256:
			return 32;
		case CONG_ALG_SHA512:
			return 64;
	}
	return 0;
}

/* The grammar of one template segment, shared by the loader that validates it
 * and the renderer that applies it, so a token cannot be accepted by one and
 * read differently by the other. */
enum scheme_token_kind {
	TOKEN_LITERAL,   /* one ordinary byte */
	TOKEN_PERCENT,   /* "%%" */
	TOKEN_GROUP,     /* "%uN" or "%cN" */
	TOKEN_BAD
};

static enum scheme_token_kind scheme_token_at(const char *seg, size_t len, size_t *i,
		int *index, bool *from_user)
{
	size_t start = *i;

	if(seg[start] != '%'){
		*i = start + 1;
		return TOKEN_LITERAL;
	}
	if(start + 1 < len && seg[start + 1] == '%'){
		*i = start + 2;
		return TOKEN_PERCENT;
	}
	/* A percent must open a group reference. "%" on its own, "%u" with no number
	 * and "%1" with no source are all guesses about the password, and a guess
	 * that digests is a password no device can compute. Group numbers are a
	 * single digit (the capture limit is CONG_MAX_GROUPS - 1), so the byte after
	 * a valid reference is literal text again. */
	if(start + 2 >= len || (seg[start + 1] != 'u' && seg[start + 1] != 'c')
			|| seg[start + 2] < '1' || seg[start + 2] > '9'){
		return TOKEN_BAD;
	}
	*index = seg[start + 2] - '0';
	*from_user = (seg[start + 1] == 'u');
	*i = start + 3;
	return TOKEN_GROUP;
}

/* Records which identities a template reaches and how far into their groups. */
static bool scheme_scan(const char *seg, size_t len, struct cong_scheme_item *item)
{
	size_t i = 0;

	while(i < len){
		int index = 0;
		bool from_user = false;

		switch(scheme_token_at(seg, len, &i, &index, &from_user)){
			case TOKEN_LITERAL:
			case TOKEN_PERCENT:
				break;
			case TOKEN_GROUP:
				if(from_user){
					item->uses_username = true;
					if(index > item->username_group){
						item->username_group = index;
					}
				}else{
					item->uses_clientid = true;
					if(index > item->clientid_group){
						item->clientid_group = index;
					}
				}
				break;
			case TOKEN_BAD:
				return false;
		}
	}
	return true;
}

static struct cong_captured scheme_group_value(const struct cong_groups *groups, int index)
{
	static const struct cong_captured none = {NULL, 0};

	/* cong_subject_match_groups() leaves count at 0 when it did not match, in
	 * which case g[] was never written; a group that did not participate in an
	 * otherwise successful match reads back as NULL text. */
	if(!groups || groups->count == 0 || index <= 0 || index >= CONG_MAX_GROUPS){
		return none;
	}
	return groups->g[index];
}

static bool scheme_emit(char *out, size_t outsize, size_t *used, const char *value, size_t value_len)
{
	if(*used + value_len > outsize){
		return false;
	}
	if(value_len > 0 && out){
		memcpy(out + *used, value, value_len);
	}
	*used += value_len;
	return true;
}

/* The literal text of a template is never cleaned - a separator of "_" would
 * delete itself - only the identity bytes taken out of a capture are. */
static bool scheme_emit_sanitized(char *out, size_t outsize, size_t *used,
		const char *value, size_t value_len, bool sanitize)
{
	size_t kept;

	if(value == NULL || value_len == 0){
		return true;
	}
	if(!sanitize){
		return scheme_emit(out, outsize, used, value, value_len);
	}
	kept = cong_sanitize_identity_n(value, value_len, out ? out + *used : NULL,
			out ? outsize - *used : 0);
	if(kept == (size_t) -1){
		return false;
	}
	*used += kept;
	return true;
}

/* out == NULL only measures. Otherwise outsize must cover the measured bytes
 * plus the terminator this walks for, which is why the caller measures first. */
static bool scheme_walk(const char *seg, size_t len, bool sanitize,
		const struct cong_groups *user_groups, const struct cong_groups *client_groups,
		char *out, size_t outsize, size_t *used)
{
	size_t i = 0;

	while(i < len){
		size_t start = i;
		int index = 0;
		bool from_user = false;
		enum scheme_token_kind kind = scheme_token_at(seg, len, &i, &index, &from_user);

		if(kind == TOKEN_BAD){
			return false;
		}
		if(kind == TOKEN_GROUP){
			const struct cong_groups *groups = from_user ? user_groups : client_groups;
			const struct cong_captured value = scheme_group_value(groups, index);

			if(!scheme_emit_sanitized(out, outsize, used, value.text, value.len, sanitize)){
				return false;
			}
		}else if(kind == TOKEN_PERCENT){
			if(!scheme_emit(out, outsize, used, "%", 1)){
				return false;
			}
		}else if(!scheme_emit(out, outsize, used, seg + start, 1)){
			return false;
		}
	}
	return true;
}

bool cong_scheme_text_build(const struct cong_scheme_item *item, bool sanitize,
		const struct cong_groups *user_groups, const struct cong_groups *client_groups,
		char **out, size_t *outlen)
{
	char *buf;
	size_t len;
	size_t need;
	size_t used = 0;

	*out = NULL;
	if(outlen){
		*outlen = 0;
	}
	if(item->part != PART_TEXT || item->text == NULL){
		return false;
	}
	len = strlen(item->text);
	/* Two passes rather than a guessed capacity: a segment that repeats a
	 * reference to a long capture has no useful static bound, and a digest must
	 * never refuse a password because a buffer was sized too small. */
	if(!scheme_walk(item->text, len, sanitize, user_groups, client_groups, NULL, SIZE_MAX, &used)){
		return false;
	}
	need = used;
	buf = malloc(need + 1);
	if(!buf){
		return false;
	}
	used = 0;
	if(!scheme_walk(item->text, len, sanitize, user_groups, client_groups, buf, need + 1, &used)){
		free(buf);
		return false;
	}
	buf[used] = '\0';
	*out = buf;
	if(outlen){
		*outlen = used;
	}
	return true;
}

bool cong_scheme_parse(const char *text, struct cong_scheme *scheme)
{
	static const struct {
		const char *name;
		enum cong_scheme_part part;
	} factors[] = {
		{ "username", PART_USERNAME },
		{ "clientid", PART_CLIENTID },
		{ "salt", PART_SALT }
	};
	const char *p = text;
	unsigned i;

	/* The caller owns nothing here yet: cong_auth.c parses into a rule it has
	 * just allocated, and the unit tests into a struct on the stack. */
	memset(scheme, 0, sizeof(struct cong_scheme));
	if(!text || text[0] == '\0'){
		return false;
	}

	for(; *p; ){
		const char *end = strchr(p, '+');
		size_t len = end ? (size_t) (end - p) : strlen(p);
		struct cong_scheme_item *item = &scheme->items[scheme->count];

		/* An empty segment ("username++salt", "+salt") is refused rather than read
		 * as an empty factor: the one place an empty factor is legitimate is the
		 * decision cong_auth.c makes about a missing identity. */
		if(len == 0 || scheme->count >= CONG_SCHEME_MAX_PARTS){
			goto fail;
		}
		item->part = PART_TEXT;
		for(i = 0; i < sizeof(factors) / sizeof(factors[0]); i++){
			if(len == strlen(factors[i].name) && !strncmp(p, factors[i].name, len)){
				item->part = factors[i].part;
				break;
			}
		}
		switch(item->part){
			case PART_USERNAME:
				item->uses_username = true;
				break;
			case PART_CLIENTID:
				item->uses_clientid = true;
				break;
			case PART_SALT:
				break;
			case PART_TEXT:
				if(!scheme_scan(p, len, item)){
					goto fail;
				}
				item->text = strndup(p, len);
				if(!item->text){
					goto fail;
				}
				break;
		}
		scheme->count++;

		if(!end){
			break;
		}
		p = end + 1;
		if(*p == '\0'){
			/* trailing separator */
			goto fail;
		}
	}
	return scheme->count > 0;

fail:
	cong_scheme_free(scheme);
	return false;
}

void cong_scheme_free(struct cong_scheme *scheme)
{
	unsigned i;

	for(i = 0; i < scheme->count; i++){
		free(scheme->items[i].text);
	}
	memset(scheme, 0, sizeof(struct cong_scheme));
}

void cong_scheme_usage(const struct cong_scheme *scheme, struct cong_scheme_use *use)
{
	unsigned i;

	memset(use, 0, sizeof(struct cong_scheme_use));
	for(i = 0; i < scheme->count; i++){
		const struct cong_scheme_item *item = &scheme->items[i];

		if(item->part == PART_SALT){
			use->salt = true;
		}
		if(item->uses_username){
			use->username = true;
			if(item->username_group > use->username_groups){
				use->username_groups = item->username_group;
			}
		}
		if(item->uses_clientid){
			use->clientid = true;
			if(item->clientid_group > use->clientid_groups){
				use->clientid_groups = item->clientid_group;
			}
		}
	}
}

int cong_digest_parts(enum cong_alg alg, uint8_t *out, size_t outsize, size_t *outlen,
		const struct cong_digest_part *parts, unsigned part_count)
{
	const EVP_MD *md;
	EVP_MD_CTX *ctx;
	unsigned int len = 0;
	unsigned i;
	int rc = 1;

	md = alg_to_md(alg);
	if(!md){
		return 1;
	}
	if(outsize < cong_alg_digest_len(alg)){
		return 1;
	}

	ctx = EVP_MD_CTX_new();
	if(!ctx){
		return 1;
	}
	if(EVP_DigestInit_ex(ctx, md, NULL) != 1){
		goto cleanup;
	}
	for(i = 0; i < part_count; i++){
		if(parts[i].data == NULL){
			continue;
		}
		if(EVP_DigestUpdate(ctx, parts[i].data, parts[i].len) != 1){
			goto cleanup;
		}
	}
	if(EVP_DigestFinal_ex(ctx, out, &len) != 1){
		goto cleanup;
	}
	if(outlen){
		*outlen = len;
	}
	rc = 0;

cleanup:
	EVP_MD_CTX_free(ctx);
	return rc;
}

int cong_secret_cmp(const uint8_t *a, const uint8_t *b, size_t len)
{
	if(len == 0){
		return 1;
	}
	return CRYPTO_memcmp(a, b, len);
}
