/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef _ODP_TEST_CRYPTO_VECTORS_H_
#define _ODP_TEST_CRYPTO_VECTORS_H_

#include "test_vectors_len.h"
/* TDES-CBC reference vectors, according to
 * "http://csrc.nist.gov/groups/STM/cavp/documents/des/DESMMT.pdf"
 */
static uint8_t tdes_cbc_reference_key[][TDES_CBC_KEY_LEN] = {
	{0x62, 0x7f, 0x46, 0x0e, 0x08, 0x10, 0x4a, 0x10, 0x43, 0xcd, 0x26, 0x5d,
	 0x58, 0x40, 0xea, 0xf1, 0x31, 0x3e, 0xdf, 0x97, 0xdf, 0x2a, 0x8a, 0x8c,
	 },

	{0x37, 0xae, 0x5e, 0xbf, 0x46, 0xdf, 0xf2, 0xdc, 0x07, 0x54, 0xb9, 0x4f,
	 0x31, 0xcb, 0xb3, 0x85, 0x5e, 0x7f, 0xd3, 0x6d, 0xc8, 0x70, 0xbf, 0xae}
};

static uint8_t tdes_cbc_reference_iv[][TDES_CBC_IV_LEN] = {
	{0x8e, 0x29, 0xf7, 0x5e, 0xa7, 0x7e, 0x54, 0x75},

	{0x3d, 0x1d, 0xe3, 0xcc, 0x13, 0x2e, 0x3b, 0x65}
};

/** length in bytes */
static uint32_t tdes_cbc_reference_length[] = { 8, 16 };

static uint8_t
tdes_cbc_reference_plaintext[][TDES_CBC_MAX_DATA_LEN] = {
	{0x32, 0x6a, 0x49, 0x4c, 0xd3, 0x3f, 0xe7, 0x56},

	{0x84, 0x40, 0x1f, 0x78, 0xfe, 0x6c, 0x10, 0x87, 0x6d, 0x8e, 0xa2, 0x30,
	 0x94, 0xea, 0x53, 0x09}
};

static uint8_t
tdes_cbc_reference_ciphertext[][TDES_CBC_MAX_DATA_LEN] = {
	{0xb2, 0x2b, 0x8d, 0x66, 0xde, 0x97, 0x06, 0x92},

	{0x7b, 0x1f, 0x7c, 0x7e, 0x3b, 0x1c, 0x94, 0x8e, 0xbd, 0x04, 0xa7, 0x5f,
	 0xfb, 0xa7, 0xd2, 0xf5}
};

static uint8_t aes128_cbc_reference_key[][AES128_CBC_KEY_LEN] = {
	{0x06, 0xa9, 0x21, 0x40, 0x36, 0xb8, 0xa1, 0x5b,
	 0x51, 0x2e, 0x03, 0xd5, 0x34, 0x12, 0x00, 0x06 },
	{0xc2, 0x86, 0x69, 0x6d, 0x88, 0x7c, 0x9a, 0xa0,
	 0x61, 0x1b, 0xbb, 0x3e, 0x20, 0x25, 0xa4, 0x5a },
	{0x6c, 0x3e, 0xa0, 0x47, 0x76, 0x30, 0xce, 0x21,
	 0xa2, 0xce, 0x33, 0x4a, 0xa7, 0x46, 0xc2, 0xcd },
	{0x56, 0xe4, 0x7a, 0x38, 0xc5, 0x59, 0x89, 0x74,
	 0xbc, 0x46, 0x90, 0x3d, 0xba, 0x29, 0x03, 0x49 }
};

static uint8_t aes128_cbc_reference_iv[][AES128_CBC_IV_LEN] = {
	{ 0x3d, 0xaf, 0xba, 0x42, 0x9d, 0x9e, 0xb4, 0x30,
	  0xb4, 0x22, 0xda, 0x80, 0x2c, 0x9f, 0xac, 0x41 },
	{ 0x56, 0x2e, 0x17, 0x99, 0x6d, 0x09, 0x3d, 0x28,
	  0xdd, 0xb3, 0xba, 0x69, 0x5a, 0x2e, 0x6f, 0x58 },
	{ 0xc7, 0x82, 0xdc, 0x4c, 0x09, 0x8c, 0x66, 0xcb,
	  0xd9, 0xcd, 0x27, 0xd8, 0x25, 0x68, 0x2c, 0x81 },
	{ 0x8c, 0xe8, 0x2e, 0xef, 0xbe, 0xa0, 0xda, 0x3c,
	  0x44, 0x69, 0x9e, 0xd7, 0xdb, 0x51, 0xb7, 0xd9 }
};

/** length in bytes */
static uint32_t aes128_cbc_reference_length[] = { 16, 32, 48, 64 };

static uint8_t
aes128_cbc_reference_plaintext[][AES128_CBC_MAX_DATA_LEN] = {
	"Single block msg",
	{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f },
	"This is a 48-byte message (exactly 3 AES blocks)",
	{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
	  0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
	  0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
	  0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
	  0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
	  0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
	  0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
	  0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf }
};

static uint8_t
aes128_cbc_reference_ciphertext[][AES128_CBC_MAX_DATA_LEN] = {
	{ 0xe3, 0x53, 0x77, 0x9c, 0x10, 0x79, 0xae, 0xb8,
	  0x27, 0x08, 0x94, 0x2d, 0xbe, 0x77, 0x18, 0x1a },
	{ 0xd2, 0x96, 0xcd, 0x94, 0xc2, 0xcc, 0xcf, 0x8a,
	  0x3a, 0x86, 0x30, 0x28, 0xb5, 0xe1, 0xdc, 0x0a,
	  0x75, 0x86, 0x60, 0x2d, 0x25, 0x3c, 0xff, 0xf9,
	  0x1b, 0x82, 0x66, 0xbe, 0xa6, 0xd6, 0x1a, 0xb1 },
	{ 0xd0, 0xa0, 0x2b, 0x38, 0x36, 0x45, 0x17, 0x53,
	  0xd4, 0x93, 0x66, 0x5d, 0x33, 0xf0, 0xe8, 0x86,
	  0x2d, 0xea, 0x54, 0xcd, 0xb2, 0x93, 0xab, 0xc7,
	  0x50, 0x69, 0x39, 0x27, 0x67, 0x72, 0xf8, 0xd5,
	  0x02, 0x1c, 0x19, 0x21, 0x6b, 0xad, 0x52, 0x5c,
	  0x85, 0x79, 0x69, 0x5d, 0x83, 0xba, 0x26, 0x84 },
	{ 0xc3, 0x0e, 0x32, 0xff, 0xed, 0xc0, 0x77, 0x4e,
	  0x6a, 0xff, 0x6a, 0xf0, 0x86, 0x9f, 0x71, 0xaa,
	  0x0f, 0x3a, 0xf0, 0x7a, 0x9a, 0x31, 0xa9, 0xc6,
	  0x84, 0xdb, 0x20, 0x7e, 0xb0, 0xef, 0x8e, 0x4e,
	  0x35, 0x90, 0x7a, 0xa6, 0x32, 0xc3, 0xff, 0xdf,
	  0x86, 0x8b, 0xb7, 0xb2, 0x9d, 0x3d, 0x46, 0xad,
	  0x83, 0xce, 0x9f, 0x9a, 0x10, 0x2e, 0xe9, 0x9d,
	  0x49, 0xa5, 0x3e, 0x87, 0xf4, 0xc3, 0xda, 0x55 }
};

/* AES-GCM test vectors extracted from
 * https://tools.ietf.org/html/draft-mcgrew-gcm-test-01#section-2
 */
static uint8_t aes128_gcm_reference_key[][AES128_GCM_KEY_LEN] = {
	{ 0x4c, 0x80, 0xcd, 0xef, 0xbb, 0x5d, 0x10, 0xda,
	  0x90, 0x6a, 0xc7, 0x3c, 0x36, 0x13, 0xa6, 0x34 },
	{ 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
	  0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08 },
	{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	{ 0x3d, 0xe0, 0x98, 0x74, 0xb3, 0x88, 0xe6, 0x49,
	  0x19, 0x88, 0xd0, 0xc3, 0x60, 0x7e, 0xae, 0x1f }
};

static uint8_t aes128_gcm_reference_iv[][AES128_GCM_IV_LEN] = {
	{ 0x2e, 0x44, 0x3b, 0x68, 0x49, 0x56, 0xed, 0x7e,
	  0x3b, 0x24, 0x4c, 0xfe },
	{ 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
	  0xde, 0xca, 0xf8, 0x88 },
	{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00 },
	{ 0x57, 0x69, 0x0e, 0x43, 0x4e, 0x28, 0x00, 0x00,
	  0xa2, 0xfc, 0xa1, 0xa3 }
};

static uint32_t aes128_gcm_reference_length[] = { 84, 72, 72, 40};

static uint32_t aes128_gcm_reference_tag_length[] = { 16, 16, 16, 16};

static odp_packet_data_range_t aes128_gcm_cipher_range[] = {
	{ .offset = 12, .length = 72 },
	{ .offset = 8, .length = 64 },
	{ .offset = 8, .length = 64 },
	{ .offset = 12, .length = 28 },
};

static odp_packet_data_range_t aes128_gcm_auth_range[] = {
	{ .offset = 0, .length = 84 },
	{ .offset = 0, .length = 72 },
	{ .offset = 0, .length = 72 },
	{ .offset = 0, .length = 40 },
};

static uint8_t
aes128_gcm_reference_plaintext[][AES128_GCM_MAX_DATA_LEN] = {
	{ /* Aad */
	  0x00, 0x00, 0x43, 0x21, 0x87, 0x65, 0x43, 0x21,
	  0x00, 0x00, 0x00, 0x00,
	  /* Plain */
	  0x45, 0x00, 0x00, 0x48, 0x69, 0x9a, 0x00, 0x00,
	  0x80, 0x11, 0x4d, 0xb7, 0xc0, 0xa8, 0x01, 0x02,
	  0xc0, 0xa8, 0x01, 0x01, 0x0a, 0x9b, 0xf1, 0x56,
	  0x38, 0xd3, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x04, 0x5f, 0x73, 0x69,
	  0x70, 0x04, 0x5f, 0x75, 0x64, 0x70, 0x03, 0x73,
	  0x69, 0x70, 0x09, 0x63, 0x79, 0x62, 0x65, 0x72,
	  0x63, 0x69, 0x74, 0x79, 0x02, 0x64, 0x6b, 0x00,
	  0x00, 0x21, 0x00, 0x01, 0x01, 0x02, 0x02, 0x01 },

	{ /* Aad */
	  0x00, 0x00, 0xa5, 0xf8, 0x00, 0x00, 0x00, 0x0a,
	  /* Plain */
	  0x45, 0x00, 0x00, 0x3e, 0x69, 0x8f, 0x00, 0x00,
	  0x80, 0x11, 0x4d, 0xcc, 0xc0, 0xa8, 0x01, 0x02,
	  0xc0, 0xa8, 0x01, 0x01, 0x0a, 0x98, 0x00, 0x35,
	  0x00, 0x2a, 0x23, 0x43, 0xb2, 0xd0, 0x01, 0x00,
	  0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x03, 0x73, 0x69, 0x70, 0x09, 0x63, 0x79, 0x62,
	  0x65, 0x72, 0x63, 0x69, 0x74, 0x79, 0x02, 0x64,
	  0x6b, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01 },

	{ /* Aad */
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	  /* Plain */
	  0x45, 0x00, 0x00, 0x3c, 0x99, 0xc5, 0x00, 0x00,
	  0x80, 0x01, 0xcb, 0x7a, 0x40, 0x67, 0x93, 0x18,
	  0x01, 0x01, 0x01, 0x01, 0x08, 0x00, 0x07, 0x5c,
	  0x02, 0x00, 0x44, 0x00, 0x61, 0x62, 0x63, 0x64,
	  0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c,
	  0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74,
	  0x75, 0x76, 0x77, 0x61, 0x62, 0x63, 0x64, 0x65,
	  0x66, 0x67, 0x68, 0x69, 0x01, 0x02, 0x02, 0x01 },

	{ /* Aad */
	  0x42, 0xf6, 0x7e, 0x3f, 0x10, 0x10, 0x10, 0x10,
	  0x10, 0x10, 0x10, 0x10,
	  /* Plain */
	  0x45, 0x00, 0x00, 0x1c, 0x42, 0xa2, 0x00, 0x00,
	  0x80, 0x01, 0x44, 0x1f, 0x40, 0x67, 0x93, 0xb6,
	  0xe0, 0x00, 0x00, 0x02, 0x0a, 0x00, 0xf5, 0xff,
	  0x01, 0x02, 0x02, 0x01 }
};

static uint8_t
aes128_gcm_reference_ciphertext[][AES128_GCM_MAX_DATA_LEN] = {
	{ /* Aad */
	  0x00, 0x00, 0x43, 0x21, 0x87, 0x65, 0x43, 0x21,
	  0x00, 0x00, 0x00, 0x00,
	  /* Plain */
	  0xfe, 0xcf, 0x53, 0x7e, 0x72, 0x9d, 0x5b, 0x07,
	  0xdc, 0x30, 0xdf, 0x52, 0x8d, 0xd2, 0x2b, 0x76,
	  0x8d, 0x1b, 0x98, 0x73, 0x66, 0x96, 0xa6, 0xfd,
	  0x34, 0x85, 0x09, 0xfa, 0x13, 0xce, 0xac, 0x34,
	  0xcf, 0xa2, 0x43, 0x6f, 0x14, 0xa3, 0xf3, 0xcf,
	  0x65, 0x92, 0x5b, 0xf1, 0xf4, 0xa1, 0x3c, 0x5d,
	  0x15, 0xb2, 0x1e, 0x18, 0x84, 0xf5, 0xff, 0x62,
	  0x47, 0xae, 0xab, 0xb7, 0x86, 0xb9, 0x3b, 0xce,
	  0x61, 0xbc, 0x17, 0xd7, 0x68, 0xfd, 0x97, 0x32,
	  /* Digest */
	  0x45, 0x90, 0x18, 0x14, 0x8f, 0x6c, 0xbe, 0x72,
	  0x2f, 0xd0, 0x47, 0x96, 0x56, 0x2d, 0xfd, 0xb4  },

	{ /* Aad */
	  0x00, 0x00, 0xa5, 0xf8, 0x00, 0x00, 0x00, 0x0a,
	  /* Plain */
	  0xde, 0xb2, 0x2c, 0xd9, 0xb0, 0x7c, 0x72, 0xc1,
	  0x6e, 0x3a, 0x65, 0xbe, 0xeb, 0x8d, 0xf3, 0x04,
	  0xa5, 0xa5, 0x89, 0x7d, 0x33, 0xae, 0x53, 0x0f,
	  0x1b, 0xa7, 0x6d, 0x5d, 0x11, 0x4d, 0x2a, 0x5c,
	  0x3d, 0xe8, 0x18, 0x27, 0xc1, 0x0e, 0x9a, 0x4f,
	  0x51, 0x33, 0x0d, 0x0e, 0xec, 0x41, 0x66, 0x42,
	  0xcf, 0xbb, 0x85, 0xa5, 0xb4, 0x7e, 0x48, 0xa4,
	  0xec, 0x3b, 0x9b, 0xa9, 0x5d, 0x91, 0x8b, 0xd1,
	  /* Digest */
	  0x83, 0xb7, 0x0d, 0x3a, 0xa8, 0xbc, 0x6e, 0xe4,
	  0xc3, 0x09, 0xe9, 0xd8, 0x5a, 0x41, 0xad, 0x4a },
	{ /* Aad */
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	  /* Plain */
	  0x46, 0x88, 0xda, 0xf2, 0xf9, 0x73, 0xa3, 0x92,
	  0x73, 0x29, 0x09, 0xc3, 0x31, 0xd5, 0x6d, 0x60,
	  0xf6, 0x94, 0xab, 0xaa, 0x41, 0x4b, 0x5e, 0x7f,
	  0xf5, 0xfd, 0xcd, 0xff, 0xf5, 0xe9, 0xa2, 0x84,
	  0x45, 0x64, 0x76, 0x49, 0x27, 0x19, 0xff, 0xb6,
	  0x4d, 0xe7, 0xd9, 0xdc, 0xa1, 0xe1, 0xd8, 0x94,
	  0xbc, 0x3b, 0xd5, 0x78, 0x73, 0xed, 0x4d, 0x18,
	  0x1d, 0x19, 0xd4, 0xd5, 0xc8, 0xc1, 0x8a, 0xf3,
	  /* Digest */
	  0xf8, 0x21, 0xd4, 0x96, 0xee, 0xb0, 0x96, 0xe9,
	  0x8a, 0xd2, 0xb6, 0x9e, 0x47, 0x99, 0xc7, 0x1d },

	{ /* Aad */
	  0x42, 0xf6, 0x7e, 0x3f, 0x10, 0x10, 0x10, 0x10,
	  0x10, 0x10, 0x10, 0x10,
	  /* Plain */
	  0xfb, 0xa2, 0xca, 0x84, 0x5e, 0x5d, 0xf9, 0xf0,
	  0xf2, 0x2c, 0x3e, 0x6e, 0x86, 0xdd, 0x83, 0x1e,
	  0x1f, 0xc6, 0x57, 0x92, 0xcd, 0x1a, 0xf9, 0x13,
	  0x0e, 0x13, 0x79, 0xed,
	  /* Digest */
	  0x36, 0x9f, 0x07, 0x1f, 0x35, 0xe0, 0x34, 0xbe,
	  0x95, 0xf1, 0x12, 0xe4, 0xe7, 0xd0, 0x5d, 0x35 }
};

static uint8_t hmac_md5_reference_key[][HMAC_MD5_KEY_LEN] = {
	{ 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
	  0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b },

	/* "Jefe" */
	{ 0x4a, 0x65, 0x66, 0x65 },

	{ 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa }
};

static uint32_t hmac_md5_reference_length[] = { 8, 28, 50 };

static uint8_t
hmac_md5_reference_plaintext[][HMAC_MD5_MAX_DATA_LEN] = {
	/* "Hi There" */
	{ 0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65},

	/* what do ya want for nothing?*/
	{ 0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6f, 0x20,
	  0x79, 0x61, 0x20, 0x77, 0x61, 0x6e, 0x74, 0x20,
	  0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x68,
	  0x69, 0x6e, 0x67, 0x3f },

	{ 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
	  0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
	  0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
	  0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
	  0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd }
};

static uint8_t hmac_md5_reference_digest[][HMAC_MD5_DIGEST_LEN] = {
	{ 0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c,
	  0x13, 0xf4, 0x8e, 0xf8, 0x15, 0x8b, 0xfc, 0x9d },

	{ 0x75, 0x0c, 0x78, 0x3e, 0x6a, 0xb0, 0xb5, 0x03,
	  0xea, 0xa8, 0x6e, 0x31, 0x0a, 0x5d, 0xb7, 0x38 },

	{ 0x56, 0xbe, 0x34, 0x52, 0x1d, 0x14, 0x4c, 0x88,
	  0xdb, 0xb8, 0xc7, 0x33, 0xf0, 0xe8, 0xb3, 0xf6 }
};

static uint32_t hmac_md5_reference_digest_length[] = {
	12, 12, 12
};

static uint8_t hmac_sha256_reference_key[][HMAC_SHA256_KEY_LEN] = {
	{ 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
	  0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
	  0x0b, 0x0b, 0x0b, 0x0b },

	/* "Jefe" */
	{ 0x4a, 0x65, 0x66, 0x65 },

	{ 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	  0xaa, 0xaa, 0xaa, 0xaa }
};

static uint32_t hmac_sha256_reference_length[] = { 8, 28, 50 };

static uint8_t
hmac_sha256_reference_plaintext[][HMAC_SHA256_MAX_DATA_LEN] = {
	/* "Hi There" */
	{ 0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65},

	/* what do ya want for nothing?*/
	{ 0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6f, 0x20,
	  0x79, 0x61, 0x20, 0x77, 0x61, 0x6e, 0x74, 0x20,
	  0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x68,
	  0x69, 0x6e, 0x67, 0x3f },

	{ 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
	  0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
	  0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
	  0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
	  0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd }
};

static uint8_t hmac_sha256_reference_digest[][HMAC_SHA256_DIGEST_LEN] = {
	{ 0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
	  0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b },

	{ 0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
	  0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7 },

	{ 0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46,
	  0x85, 0x4d, 0xb8, 0xeb, 0xd0, 0x91, 0x81, 0xa7 }
};

static uint32_t hmac_sha256_reference_digest_length[] = {
	16, 16, 16
};

#endif
