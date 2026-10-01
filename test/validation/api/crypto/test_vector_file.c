/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Nokia
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libconfig.h>
#include <odp/helper/odph_api.h>

#include "test_vector_file.h"

#define FILE_VERSION 1

static test_vector_set_t *sets;
static int num_sets;

int test_vector_file_num_sets(void)
{
	return num_sets;
}

const test_vector_set_t *test_vector_file_set(int index)
{
	return &sets[index];
}

void test_vector_file_free(void)
{
	for (int i = 0; i < num_sets; i++) {
		free(sets[i].location);
		free(sets[i].refs);
	}
	free(sets);
	sets = NULL;
	num_sets = 0;
}

static int fail_at(const config_setting_t *setting, const char *msg)
{
	ODPH_ERR("%s:%d: %s\n",
		 config_setting_source_file(setting),
		 config_setting_source_line(setting),
		 msg);
	return -1;
}

static int unknown_setting(const config_setting_t *setting)
{
	char msg[80];

	snprintf(msg, sizeof(msg), "unknown setting \"%s\"", config_setting_name(setting));
	return fail_at(setting, msg);
}

static int is_set_field(const char *name)
{
	return !strcmp(name, "cipher") || !strcmp(name, "auth");
}

static int is_vector_field(const char *name)
{
	/* Keep in sync with the settings read by parse_vector() */
	static const char *const fields[] = {
		"cipher_key", "cipher_key_length",
		"auth_key", "auth_key_length",
		"cipher_iv", "cipher_iv_length",
		"auth_iv", "auth_iv_length",
		"plaintext", "ciphertext",
		"aad", "aad_length",
		"digest", "digest_length",
		"length", "length_bits",
	};

	for (size_t i = 0; i < ODPH_ARRAY_SIZE(fields); i++) {
		if (!strcmp(name, fields[i]))
			return 1;
	}

	return 0;
}

static int check_vector_fields(const config_setting_t *vector)
{
	int n = config_setting_length(vector);

	for (int i = 0; i < n; i++) {
		const config_setting_t *member = config_setting_get_elem(vector, i);
		const char *name = config_setting_name(member);

		if (is_vector_field(name))
			continue;
		if (is_set_field(name))
			return fail_at(member, "algorithms are set per test vector set, "
				       "not per test vector");

		return unknown_setting(member);
	}

	return 0;
}

static int hex_digit(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;

	return -1;
}

/*
 * Parse an optional hex string setting. The length is zero when not set.
 * Spaces are allowed between bytes, but not within a byte.
 */
static int parse_hex(const config_setting_t *vector, const char *name,
		     uint8_t *dst, uint32_t max_len, uint32_t *len)
{
	const config_setting_t *setting = config_setting_get_member(vector, name);
	const char *p;
	uint32_t n = 0;

	*len = 0;
	if (!setting)
		return 0;
	if (config_setting_type(setting) != CONFIG_TYPE_STRING)
		return fail_at(setting, "expected a string");

	p = config_setting_get_string(setting);
	while (1) {
		int hi, lo;

		while (*p == ' ')
			p++;
		if (*p == '\0')
			break;
		if (p[1] == '\0' || p[1] == ' ')
			return fail_at(setting, "hex string has a byte with a single digit");

		hi = hex_digit(p[0]);
		lo = hex_digit(p[1]);
		if (hi < 0 || lo < 0)
			return fail_at(setting, "invalid hex digit");
		if (n == max_len)
			return fail_at(setting, "hex string is too long");

		dst[n++] = (uint8_t)((hi << 4) | lo);
		p += 2;
	}

	*len = n;
	return 0;
}

static int read_u32(const config_setting_t *setting, uint32_t *value)
{
	long long v;

	if (config_setting_type(setting) == CONFIG_TYPE_INT)
		v = config_setting_get_int(setting);
	else if (config_setting_type(setting) == CONFIG_TYPE_INT64)
		v = config_setting_get_int64(setting);
	else
		return fail_at(setting, "expected an integer");

	if (v < 0 || v > UINT32_MAX)
		return fail_at(setting, "integer out of range");

	*value = (uint32_t)v;
	return 0;
}

/*
 * The length is the hex data length, unless an explicit length is set.
 * An explicit length may be shorter than the hex data, but not longer.
 */
static int parse_length(const config_setting_t *vector, const char *name,
			uint32_t data_len, uint32_t *len)
{
	const config_setting_t *setting = config_setting_get_member(vector, name);

	*len = data_len;
	if (!setting)
		return 0;
	if (read_u32(setting, len))
		return -1;
	if (*len > data_len)
		return fail_at(setting, "length exceeds the hex data length");

	return 0;
}

static int parse_bytes(const config_setting_t *vector, const char *data_name,
		       const char *len_name, uint8_t *dst, uint32_t max_len,
		       uint32_t *len)
{
	uint32_t data_len;

	if (parse_hex(vector, data_name, dst, max_len, &data_len))
		return -1;

	return parse_length(vector, len_name, data_len, len);
}

/* Get the algorithm name. The name is NULL when not set. */
static int get_alg_name(const config_setting_t *set, const char *field,
			const char **name)
{
	const config_setting_t *setting = config_setting_get_member(set, field);

	*name = NULL;
	if (!setting)
		return 0;
	if (config_setting_type(setting) != CONFIG_TYPE_STRING)
		return fail_at(setting, "expected a string");

	*name = config_setting_get_string(setting);
	return 0;
}

static int unknown_alg(const config_setting_t *set, const char *field,
		       const char *name)
{
	char msg[80];

	snprintf(msg, sizeof(msg), "unknown algorithm \"%s\"", name);
	return fail_at(config_setting_get_member(set, field), msg);
}

static int parse_cipher(const config_setting_t *set, odp_cipher_alg_t *alg)
{
	const char *name;

	*alg = ODP_CIPHER_ALG_NULL;
	if (get_alg_name(set, "cipher", &name))
		return -1;
	if (!name)
		return 0;
	if (odph_cipher_alg_from_str(name, alg))
		return unknown_alg(set, "cipher", name);

	return 0;
}

static int parse_auth(const config_setting_t *set, odp_auth_alg_t *alg)
{
	const char *name;

	*alg = ODP_AUTH_ALG_NULL;
	if (get_alg_name(set, "auth", &name))
		return -1;
	if (!name)
		return 0;
	if (odph_auth_alg_from_str(name, alg))
		return unknown_alg(set, "auth", name);

	return 0;
}

static int parse_data(const config_setting_t *vector, crypto_test_reference_t *ref)
{
	const config_setting_t *ciphertext, *length_bits;
	uint32_t pt_len, ct_len;

	if (parse_hex(vector, "plaintext", ref->plaintext, MAX_DATA_LEN, &pt_len))
		return -1;

	ciphertext = config_setting_get_member(vector, "ciphertext");
	if (ciphertext) {
		if (parse_hex(vector, "ciphertext", ref->ciphertext, MAX_DATA_LEN,
			      &ct_len))
			return -1;
		if (ct_len != pt_len)
			return fail_at(ciphertext, "ciphertext length differs from plaintext");
	} else {
		memcpy(ref->ciphertext, ref->plaintext, pt_len);
	}

	length_bits = config_setting_get_member(vector, "length_bits");
	if (!length_bits)
		return parse_length(vector, "length", pt_len, &ref->length);

	if (config_setting_get_member(vector, "length"))
		return fail_at(length_bits, "length and length_bits cannot both be set");
	if (read_u32(length_bits, &ref->length))
		return -1;
	if (((uint64_t)ref->length + 7) / 8 != pt_len)
		return fail_at(length_bits, "plaintext size does not match length_bits");

	ref->is_length_in_bits = true;
	return 0;
}

static int parse_vector(const config_setting_t *vector, crypto_test_reference_t *ref)
{
	if (check_vector_fields(vector))
		return -1;

	if (parse_bytes(vector, "cipher_key", "cipher_key_length",
			ref->cipher_key, MAX_KEY_LEN, &ref->cipher_key_length) ||
	    parse_bytes(vector, "auth_key", "auth_key_length",
			ref->auth_key, MAX_KEY_LEN, &ref->auth_key_length) ||
	    parse_bytes(vector, "cipher_iv", "cipher_iv_length",
			ref->cipher_iv, MAX_IV_LEN, &ref->cipher_iv_length) ||
	    parse_bytes(vector, "auth_iv", "auth_iv_length",
			ref->auth_iv, MAX_IV_LEN, &ref->auth_iv_length) ||
	    parse_bytes(vector, "aad", "aad_length",
			ref->aad, MAX_AAD_LEN, &ref->aad_length) ||
	    parse_bytes(vector, "digest", "digest_length",
			ref->digest, MAX_DIGEST_LEN, &ref->digest_length))
		return -1;

	return parse_data(vector, ref);
}

static char *format_location(const config_setting_t *setting)
{
	const char *file = config_setting_source_file(setting);
	int line = config_setting_source_line(setting);
	const char *name = config_setting_name(setting);
	int len = snprintf(NULL, 0, "%s:%d: %s", file, line, name);
	char *location = malloc(len + 1);

	if (location)
		snprintf(location, len + 1, "%s:%d: %s", file, line, name);

	return location;
}

static int is_vector(const config_setting_t *setting)
{
	return config_setting_type(setting) == CONFIG_TYPE_GROUP;
}

/*
 * Check the set level settings and count the test vectors. The test vectors
 * are the groups within the set. The other settings are set level fields.
 */
static int check_set_fields(const config_setting_t *set, int *num_vectors)
{
	int n = config_setting_length(set);

	*num_vectors = 0;
	for (int i = 0; i < n; i++) {
		const config_setting_t *member = config_setting_get_elem(set, i);

		if (is_vector(member))
			(*num_vectors)++;
		else if (!is_set_field(config_setting_name(member)))
			return unknown_setting(member);
	}

	if (*num_vectors == 0)
		return fail_at(set, "no test vectors in the set");

	return 0;
}

static int parse_set(const config_setting_t *setting, test_vector_set_t *set)
{
	odp_cipher_alg_t cipher;
	odp_auth_alg_t auth;
	int n, num_vectors;

	if (config_setting_type(setting) != CONFIG_TYPE_GROUP)
		return fail_at(setting, "expected a group of test vectors");
	if (check_set_fields(setting, &num_vectors) ||
	    parse_cipher(setting, &cipher) ||
	    parse_auth(setting, &auth))
		return -1;

	set->location = format_location(setting);
	set->refs = calloc(num_vectors, sizeof(*set->refs));
	if (!set->location || !set->refs) {
		ODPH_ERR("allocating test vectors failed\n");
		return -1;
	}
	set->num_refs = num_vectors;

	n = config_setting_length(setting);
	for (int i = 0, v = 0; i < n; i++) {
		const config_setting_t *vector = config_setting_get_elem(setting, i);
		crypto_test_reference_t *ref;

		if (!is_vector(vector))
			continue;

		ref = &set->refs[v++];
		ref->cipher = cipher;
		ref->auth = auth;
		if (parse_vector(vector, ref))
			return -1;
	}

	return 0;
}

static int check_version(const config_setting_t *root, const char *filename)
{
	const config_setting_t *version = config_setting_get_member(root, "version");

	if (!version) {
		ODPH_ERR("%s: version is missing\n", filename);
		return -1;
	}
	if (config_setting_type(version) != CONFIG_TYPE_INT)
		return fail_at(version, "version must be an integer");
	if (config_setting_get_int(version) != FILE_VERSION)
		return fail_at(version, "unsupported test vector file version");

	return 0;
}

static int parse_file(const config_t *cfg, const char *filename)
{
	const config_setting_t *root = config_root_setting(cfg);
	int n = config_setting_length(root);
	int first_set = num_sets;
	test_vector_set_t *new_sets;

	if (check_version(root, filename))
		return -1;

	new_sets = realloc(sets, (num_sets + n) * sizeof(*sets));
	if (!new_sets) {
		ODPH_ERR("allocating test vector sets failed\n");
		return -1;
	}
	sets = new_sets;
	memset(&sets[num_sets], 0, n * sizeof(*sets));

	for (int i = 0; i < n; i++) {
		const config_setting_t *setting = config_setting_get_elem(root, i);

		if (!strcmp(config_setting_name(setting), "version"))
			continue;

		/* Count the set first, so that test_vector_file_free() frees it on failure */
		if (parse_set(setting, &sets[num_sets++]))
			return -1;
	}

	if (num_sets == first_set) {
		ODPH_ERR("%s: no test vectors\n", filename);
		return -1;
	}

	return 0;
}

int test_vector_file_load(const char *filename)
{
	config_t cfg;
	int rc;

	config_init(&cfg);
	if (!config_read_file(&cfg, filename)) {
		ODPH_ERR("%s:%d: %s\n", filename,
			 config_error_line(&cfg),
			 config_error_text(&cfg));
		config_destroy(&cfg);
		return -1;
	}

	rc = parse_file(&cfg, filename);
	config_destroy(&cfg);
	if (rc)
		test_vector_file_free();

	return rc;
}
