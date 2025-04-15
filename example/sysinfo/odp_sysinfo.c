/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 * Copyright (c) 2022-2025 Nokia
 */

 /**
  * @example odp_sysinfo.c
  *
  * Example application which queries and prints out various system information
  * and capabilities which are available through ODP APIs.
  *
  * @cond _ODP_HIDE_FROM_DOXYGEN_
  */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#define KB              1024
#define MB              (1024 * 1024)
#define MAX_HUGE_PAGES  32
#define MAX_IFACES      32
#define MAX_NAME_LEN    128

#define PROG_NAME "odp_sysinfo"

typedef struct {
	char name[MAX_NAME_LEN];
	odp_pktio_capability_t capa;
	odp_proto_stats_capability_t proto_stats_capa;
} pktio_t;

typedef struct {
	int num_pktio;
	pktio_t pktio[MAX_IFACES];
	struct {
		odp_timer_capability_t capa[ODP_CLOCK_NUM_SRC];
		odp_timer_pool_info_t pool_info[ODP_CLOCK_NUM_SRC];
		int num;
	} timer;
} appl_args_t;

/* Check that prints can use %u instead of %PRIu32 */
ODP_STATIC_ASSERT(sizeof(unsigned int) >= sizeof(uint32_t), "unsigned int smaller than uint32_t");

static const char *support_level(odp_support_t support)
{
	switch (support) {
	case ODP_SUPPORT_NO: return "no";
	case ODP_SUPPORT_YES: return "yes";
	case ODP_SUPPORT_PREFERRED: return "yes, preferred";
	default: return "UNKNOWN";
	}
}

static const char *cpu_arch_name(odp_system_info_t *sysinfo)
{
	odp_cpu_arch_t cpu_arch = sysinfo->cpu_arch;

	switch (cpu_arch) {
	case ODP_CPU_ARCH_ARM:
		return "ARM";
	case ODP_CPU_ARCH_MIPS:
		return "MIPS";
	case ODP_CPU_ARCH_PPC:
		return "PPC";
	case ODP_CPU_ARCH_RISCV:
		return "RISC-V";
	case ODP_CPU_ARCH_X86:
		return "x86";
	default:
		return "Unknown";
	}
}

static const char *arm_isa(odp_cpu_arch_arm_t isa)
{
	switch (isa) {
	case ODP_CPU_ARCH_ARMV6:
		return "ARMv6";
	case ODP_CPU_ARCH_ARMV7:
		return "ARMv7-A";
	case ODP_CPU_ARCH_ARMV8_0:
		return "ARMv8.0-A";
	case ODP_CPU_ARCH_ARMV8_1:
		return "ARMv8.1-A";
	case ODP_CPU_ARCH_ARMV8_2:
		return "ARMv8.2-A";
	case ODP_CPU_ARCH_ARMV8_3:
		return "ARMv8.3-A";
	case ODP_CPU_ARCH_ARMV8_4:
		return "ARMv8.4-A";
	case ODP_CPU_ARCH_ARMV8_5:
		return "ARMv8.5-A";
	case ODP_CPU_ARCH_ARMV8_6:
		return "ARMv8.6-A";
	case ODP_CPU_ARCH_ARMV8_7:
		return "ARMv8.7-A";
	case ODP_CPU_ARCH_ARMV8_8:
		return "ARMv8.8-A";
	case ODP_CPU_ARCH_ARMV8_9:
		return "ARMv8.9-A";
	case ODP_CPU_ARCH_ARMV9_0:
		return "ARMv9.0-A";
	case ODP_CPU_ARCH_ARMV9_1:
		return "ARMv9.1-A";
	case ODP_CPU_ARCH_ARMV9_2:
		return "ARMv9.2-A";
	case ODP_CPU_ARCH_ARMV9_3:
		return "ARMv9.3-A";
	default:
		return "Unknown";
	}
}

static const char *x86_isa(odp_cpu_arch_x86_t isa)
{
	switch (isa) {
	case ODP_CPU_ARCH_X86_I686:
		return "x86_i686";
	case ODP_CPU_ARCH_X86_64:
		return "x86_64";
	default:
		return "Unknown";
	}
}

static const char *cpu_arch_isa(odp_system_info_t *sysinfo, int isa_sw)
{
	odp_cpu_arch_t cpu_arch = sysinfo->cpu_arch;

	switch (cpu_arch) {
	case ODP_CPU_ARCH_ARM:
		if (isa_sw)
			return arm_isa(sysinfo->cpu_isa_sw.arm);
		else
			return arm_isa(sysinfo->cpu_isa_hw.arm);
	case ODP_CPU_ARCH_MIPS:
		return "Unknown";
	case ODP_CPU_ARCH_PPC:
		return "Unknown";
	case ODP_CPU_ARCH_RISCV:
		return "Unknown";
	case ODP_CPU_ARCH_X86:
		if (isa_sw)
			return x86_isa(sysinfo->cpu_isa_sw.x86);
		else
			return x86_isa(sysinfo->cpu_isa_hw.x86);
	default:
		return "Unknown";
	}
}

static const char *cipher_alg_name(odp_cipher_alg_t cipher)
{
	switch (cipher) {
	case ODP_CIPHER_ALG_NULL:
		return "null";
	case ODP_CIPHER_ALG_DES:
		return "des";
	case ODP_CIPHER_ALG_3DES_CBC:
		return "3des_cbc";
	case ODP_CIPHER_ALG_3DES_ECB:
		return "3des_ecb";
	case ODP_CIPHER_ALG_AES_CBC:
		return "aes_cbc";
	case ODP_CIPHER_ALG_AES_CTR:
		return "aes_ctr";
	case ODP_CIPHER_ALG_AES_ECB:
		return "aes_ecb";
	case ODP_CIPHER_ALG_AES_CFB128:
		return "aes_cfb128";
	case ODP_CIPHER_ALG_AES_XTS:
		return "aes_xts";
	case ODP_CIPHER_ALG_AES_GCM:
		return "aes_gcm";
	case ODP_CIPHER_ALG_AES_CCM:
		return "aes_ccm";
	case ODP_CIPHER_ALG_CHACHA20_POLY1305:
		return "chacha20_poly1305";
	case ODP_CIPHER_ALG_KASUMI_F8:
		return "kasumi_f8";
	case ODP_CIPHER_ALG_SNOW3G_UEA2:
		return "snow3g_uea2";
	case ODP_CIPHER_ALG_AES_EEA2:
		return "aes_eea2";
	case ODP_CIPHER_ALG_ZUC_EEA3:
		return "zuc_eea3";
	case ODP_CIPHER_ALG_SNOW_V:
		return "snow_v";
	case ODP_CIPHER_ALG_SNOW_V_GCM:
		return "snow_v_gcm";
	case ODP_CIPHER_ALG_SM4_ECB:
		return "sm4_ecb";
	case ODP_CIPHER_ALG_SM4_CBC:
		return "sm4_cbc";
	case ODP_CIPHER_ALG_SM4_CTR:
		return "sm4_ctr";
	case ODP_CIPHER_ALG_SM4_GCM:
		return "sm4_gcm";
	case ODP_CIPHER_ALG_SM4_CCM:
		return "sm4_ccm";
	default:
		return "Unknown";
	}
}

static const char *auth_alg_name(odp_auth_alg_t auth)
{
	switch (auth) {
	case ODP_AUTH_ALG_NULL:
		return "null";
	case ODP_AUTH_ALG_MD5_HMAC:
		return "md5_hmac";
	case ODP_AUTH_ALG_SHA1_HMAC:
		return "sha1_hmac";
	case ODP_AUTH_ALG_SHA224_HMAC:
		return "sha224_hmac";
	case ODP_AUTH_ALG_SHA256_HMAC:
		return "sha256_hmac";
	case ODP_AUTH_ALG_SHA384_HMAC:
		return "sha384_hmac";
	case ODP_AUTH_ALG_SHA512_HMAC:
		return "sha512_hmac";
	case ODP_AUTH_ALG_SHA3_224_HMAC:
		return "sha3_224_hmac";
	case ODP_AUTH_ALG_SHA3_256_HMAC:
		return "sha3_256_hmac";
	case ODP_AUTH_ALG_SHA3_384_HMAC:
		return "sha3_384_hmac";
	case ODP_AUTH_ALG_SHA3_512_HMAC:
		return "sha3_512_hmac";
	case ODP_AUTH_ALG_AES_GCM:
		return "aes_gcm";
	case ODP_AUTH_ALG_AES_GMAC:
		return "aes_gmac";
	case ODP_AUTH_ALG_AES_CCM:
		return "aes_ccm";
	case ODP_AUTH_ALG_AES_CMAC:
		return "aes_cmac";
	case ODP_AUTH_ALG_AES_XCBC_MAC:
		return "aes_xcbc_mac";
	case ODP_AUTH_ALG_CHACHA20_POLY1305:
		return "chacha20_poly1305";
	case ODP_AUTH_ALG_KASUMI_F9:
		return "kasumi_f9";
	case ODP_AUTH_ALG_SNOW3G_UIA2:
		return "snow3g_uia2";
	case ODP_AUTH_ALG_AES_EIA2:
		return "aes_eia2";
	case ODP_AUTH_ALG_ZUC_EIA3:
		return "zuc_eia3";
	case ODP_AUTH_ALG_SNOW_V_GCM:
		return "snow_v_gcm";
	case ODP_AUTH_ALG_SNOW_V_GMAC:
		return "snow_v_gmac";
	case ODP_AUTH_ALG_SM3_HMAC:
		return "sm3_hmac";
	case ODP_AUTH_ALG_SM4_GCM:
		return "sm4_gcm";
	case ODP_AUTH_ALG_SM4_GMAC:
		return "sm4_gmac";
	case ODP_AUTH_ALG_SM4_CCM:
		return "sm4_ccm";
	case ODP_AUTH_ALG_MD5:
		return "md5";
	case ODP_AUTH_ALG_SHA1:
		return "sha1";
	case ODP_AUTH_ALG_SHA224:
		return "sha224";
	case ODP_AUTH_ALG_SHA256:
		return "sha256";
	case ODP_AUTH_ALG_SHA384:
		return "sha384";
	case ODP_AUTH_ALG_SHA512:
		return "sha512";
	case ODP_AUTH_ALG_SHA3_224:
		return "sha3_224";
	case ODP_AUTH_ALG_SHA3_256:
		return "sha3_256";
	case ODP_AUTH_ALG_SHA3_384:
		return "sha3_384";
	case ODP_AUTH_ALG_SHA3_512:
		return "sha3_512";
	case ODP_AUTH_ALG_SM3:
		return "sm3";
	default:
		return "Unknown";
	}
}

typedef void (*cipher_op_t)(odp_cipher_alg_t alg);
typedef void (*auth_op_t)(odp_auth_alg_t alg);

static void foreach_cipher(odp_crypto_cipher_algos_t ciphers, cipher_op_t op)
{
	if (ciphers.bit.null)
		op(ODP_CIPHER_ALG_NULL);
	if (ciphers.bit.des)
		op(ODP_CIPHER_ALG_DES);
	if (ciphers.bit.trides_cbc)
		op(ODP_CIPHER_ALG_3DES_CBC);
	if (ciphers.bit.trides_ecb)
		op(ODP_CIPHER_ALG_3DES_ECB);
	if (ciphers.bit.aes_cbc)
		op(ODP_CIPHER_ALG_AES_CBC);
	if (ciphers.bit.aes_ctr)
		op(ODP_CIPHER_ALG_AES_CTR);
	if (ciphers.bit.aes_ecb)
		op(ODP_CIPHER_ALG_AES_ECB);
	if (ciphers.bit.aes_cfb128)
		op(ODP_CIPHER_ALG_AES_CFB128);
	if (ciphers.bit.aes_xts)
		op(ODP_CIPHER_ALG_AES_XTS);
	if (ciphers.bit.aes_gcm)
		op(ODP_CIPHER_ALG_AES_GCM);
	if (ciphers.bit.aes_ccm)
		op(ODP_CIPHER_ALG_AES_CCM);
	if (ciphers.bit.chacha20_poly1305)
		op(ODP_CIPHER_ALG_CHACHA20_POLY1305);
	if (ciphers.bit.kasumi_f8)
		op(ODP_CIPHER_ALG_KASUMI_F8);
	if (ciphers.bit.snow3g_uea2)
		op(ODP_CIPHER_ALG_SNOW3G_UEA2);
	if (ciphers.bit.aes_eea2)
		op(ODP_CIPHER_ALG_AES_EEA2);
	if (ciphers.bit.zuc_eea3)
		op(ODP_CIPHER_ALG_ZUC_EEA3);
	if (ciphers.bit.snow_v)
		op(ODP_CIPHER_ALG_SNOW_V);
	if (ciphers.bit.snow_v_gcm)
		op(ODP_CIPHER_ALG_SNOW_V_GCM);
	if (ciphers.bit.sm4_ecb)
		op(ODP_CIPHER_ALG_SM4_ECB);
	if (ciphers.bit.sm4_cbc)
		op(ODP_CIPHER_ALG_SM4_CBC);
	if (ciphers.bit.sm4_ctr)
		op(ODP_CIPHER_ALG_SM4_CTR);
	if (ciphers.bit.sm4_gcm)
		op(ODP_CIPHER_ALG_SM4_GCM);
	if (ciphers.bit.sm4_ccm)
		op(ODP_CIPHER_ALG_SM4_CCM);
}

static void foreach_auth(odp_crypto_auth_algos_t auths, auth_op_t op)
{
	if (auths.bit.null)
		op(ODP_AUTH_ALG_NULL);
	if (auths.bit.md5_hmac)
		op(ODP_AUTH_ALG_MD5_HMAC);
	if (auths.bit.sha1_hmac)
		op(ODP_AUTH_ALG_SHA1_HMAC);
	if (auths.bit.sha224_hmac)
		op(ODP_AUTH_ALG_SHA224_HMAC);
	if (auths.bit.sha256_hmac)
		op(ODP_AUTH_ALG_SHA256_HMAC);
	if (auths.bit.sha384_hmac)
		op(ODP_AUTH_ALG_SHA384_HMAC);
	if (auths.bit.sha512_hmac)
		op(ODP_AUTH_ALG_SHA512_HMAC);
	if (auths.bit.sha3_224_hmac)
		op(ODP_AUTH_ALG_SHA3_224_HMAC);
	if (auths.bit.sha3_256_hmac)
		op(ODP_AUTH_ALG_SHA3_256_HMAC);
	if (auths.bit.sha3_384_hmac)
		op(ODP_AUTH_ALG_SHA3_384_HMAC);
	if (auths.bit.sha3_512_hmac)
		op(ODP_AUTH_ALG_SHA3_512_HMAC);
	if (auths.bit.aes_gcm)
		op(ODP_AUTH_ALG_AES_GCM);
	if (auths.bit.aes_gmac)
		op(ODP_AUTH_ALG_AES_GMAC);
	if (auths.bit.aes_ccm)
		op(ODP_AUTH_ALG_AES_CCM);
	if (auths.bit.aes_cmac)
		op(ODP_AUTH_ALG_AES_CMAC);
	if (auths.bit.aes_xcbc_mac)
		op(ODP_AUTH_ALG_AES_XCBC_MAC);
	if (auths.bit.chacha20_poly1305)
		op(ODP_AUTH_ALG_CHACHA20_POLY1305);
	if (auths.bit.kasumi_f9)
		op(ODP_AUTH_ALG_KASUMI_F9);
	if (auths.bit.snow3g_uia2)
		op(ODP_AUTH_ALG_SNOW3G_UIA2);
	if (auths.bit.aes_eia2)
		op(ODP_AUTH_ALG_AES_EIA2);
	if (auths.bit.zuc_eia3)
		op(ODP_AUTH_ALG_ZUC_EIA3);
	if (auths.bit.snow_v_gcm)
		op(ODP_AUTH_ALG_SNOW_V_GCM);
	if (auths.bit.snow_v_gmac)
		op(ODP_AUTH_ALG_SNOW_V_GMAC);
	if (auths.bit.sm3_hmac)
		op(ODP_AUTH_ALG_SM3_HMAC);
	if (auths.bit.sm4_gcm)
		op(ODP_AUTH_ALG_SM4_GCM);
	if (auths.bit.sm4_gmac)
		op(ODP_AUTH_ALG_SM4_GMAC);
	if (auths.bit.sm4_ccm)
		op(ODP_AUTH_ALG_SM4_CCM);
	if (auths.bit.md5)
		op(ODP_AUTH_ALG_MD5);
	if (auths.bit.sha1)
		op(ODP_AUTH_ALG_SHA1);
	if (auths.bit.sha224)
		op(ODP_AUTH_ALG_SHA224);
	if (auths.bit.sha256)
		op(ODP_AUTH_ALG_SHA256);
	if (auths.bit.sha384)
		op(ODP_AUTH_ALG_SHA384);
	if (auths.bit.sha512)
		op(ODP_AUTH_ALG_SHA512);
	if (auths.bit.sha3_224)
		op(ODP_AUTH_ALG_SHA3_224);
	if (auths.bit.sha3_256)
		op(ODP_AUTH_ALG_SHA3_256);
	if (auths.bit.sha3_384)
		op(ODP_AUTH_ALG_SHA3_384);
	if (auths.bit.sha3_512)
		op(ODP_AUTH_ALG_SHA3_512);
	if (auths.bit.sm3)
		op(ODP_AUTH_ALG_SM3);
}

static void print_cipher_capa(odp_cipher_alg_t cipher)
{
	int caps = odp_crypto_cipher_capability(cipher, NULL, 0);
	int rc, i;

	if (caps <= 0)
		return;

	odp_crypto_cipher_capability_t capa[caps];

	rc = odp_crypto_cipher_capability(cipher, capa, caps);
	if (rc < 0)
		return;

	printf("        %s:\n", cipher_alg_name(cipher));
	for (i = 0; i < rc; i++)
		printf("            key %d iv %d\n",
		       capa[i].key_len, capa[i].iv_len);
}

static void print_auth_capa(odp_auth_alg_t auth)
{
	int caps = odp_crypto_auth_capability(auth, NULL, 0);
	int rc, i;

	if (caps <= 0)
		return;

	odp_crypto_auth_capability_t capa[caps];

	rc = odp_crypto_auth_capability(auth, capa, caps);
	if (rc < 0)
		return;

	printf("        %s:\n", auth_alg_name(auth));
	for (i = 0; i < rc; i++) {
		printf("            digest %d", capa[i].digest_len);
		if (capa[i].key_len != 0)
			printf(" key %d", capa[i].key_len);
		if (capa[i].iv_len != 0)
			printf(" iv %d", capa[i].iv_len);
		if (capa[i].aad_len.max != 0)
			printf(" aad %d, %d, %d",
			       capa[i].aad_len.min, capa[i].aad_len.max,
			       capa[i].aad_len.inc);
		printf("\n");
	}
}

static void print_cipher(odp_cipher_alg_t alg)
{
	printf("%s ", cipher_alg_name(alg));
}

static void print_auth(odp_auth_alg_t alg)
{
	printf("%s ", auth_alg_name(alg));
}

static void print_atomic_lock_free(void)
{
	odp_atomic_op_t lock_free_u64, lock_free_u128;

	odp_atomic_lock_free_u64(&lock_free_u64);
	odp_atomic_lock_free_u128(&lock_free_u128);

	printf("\n");
	printf("  ATOMICS\n");
	printf("    Lock-free odp_atomic_u64_t ops\n");
	printf("      load:	     %s\n", lock_free_u64.op.load ? "yes" : "no");
	printf("      store:	     %s\n", lock_free_u64.op.store ? "yes" : "no");
	printf("      fetch_add:     %s\n", lock_free_u64.op.fetch_add ? "yes" : "no");
	printf("      add:	     %s\n", lock_free_u64.op.add ? "yes" : "no");
	printf("      fetch_sub:     %s\n", lock_free_u64.op.fetch_sub ? "yes" : "no");
	printf("      sub:	     %s\n", lock_free_u64.op.sub ? "yes" : "no");
	printf("      fetch_inc:     %s\n", lock_free_u64.op.fetch_inc ? "yes" : "no");
	printf("      inc:	     %s\n", lock_free_u64.op.inc ? "yes" : "no");
	printf("      fetch_dec:     %s\n", lock_free_u64.op.fetch_dec ? "yes" : "no");
	printf("      dec:	     %s\n", lock_free_u64.op.dec ? "yes" : "no");
	printf("      min:	     %s\n", lock_free_u64.op.min ? "yes" : "no");
	printf("      fetch_min:     %s\n", lock_free_u64.op.fetch_min ? "yes" : "no");
	printf("      max:	     %s\n", lock_free_u64.op.max ? "yes" : "no");
	printf("      fetch_max:     %s\n", lock_free_u64.op.fetch_max ? "yes" : "no");
	printf("      cas:	     %s\n", lock_free_u64.op.cas ? "yes" : "no");
	printf("      xchg:	     %s\n", lock_free_u64.op.xchg ? "yes" : "no");
	printf("      bit_fetch_set: %s\n", lock_free_u64.op.bit_fetch_set ? "yes" : "no");
	printf("      bit_set:	     %s\n", lock_free_u64.op.bit_set ? "yes" : "no");
	printf("      bit_fetch_clr: %s\n", lock_free_u64.op.bit_fetch_clr ? "yes" : "no");
	printf("      bit_clr:	     %s\n", lock_free_u64.op.bit_clr ? "yes" : "no");
	printf("    Lock-free odp_atomic_u128_t ops\n");
	printf("      load:	     %s\n", lock_free_u128.op.load ? "yes" : "no");
	printf("      store:	     %s\n", lock_free_u128.op.store ? "yes" : "no");
	printf("      cas:	     %s\n", lock_free_u128.op.cas ? "yes" : "no");
}

static int pktio_capability(appl_args_t *appl_args)
{
	odp_pool_param_t pool_param;
	odp_pool_t pool;
	int ret = 0;

	odp_pool_param_init(&pool_param);

	pool_param.type = ODP_POOL_PACKET;
	pool_param.pkt.num = 128;

	pool = odp_pool_create("pktio_pool", &pool_param);
	if (pool == ODP_POOL_INVALID) {
		ODPH_ERR("Creating packet pool failed\n");
		return -1;
	}

	for (int i = 0; i < appl_args->num_pktio; i++) {
		odp_pktio_param_t param;
		odp_pktio_t pktio;

		odp_pktio_param_init(&param);

		param.in_mode = ODP_PKTIN_MODE_SCHED;
		param.out_mode = ODP_PKTOUT_MODE_DIRECT;

		pktio = odp_pktio_open(appl_args->pktio[i].name, pool, &param);
		if (pktio == ODP_PKTIO_INVALID) {
			ODPH_ERR("Opening pktio %s failed\n", appl_args->pktio[i].name);
			ret = -1;
			break;
		}

		if (odp_pktio_capability(pktio, &appl_args->pktio[i].capa)) {
			ODPH_ERR("Reading pktio %s capa failed\n", appl_args->pktio[i].name);
			ret = -1;
		}

		if (odp_proto_stats_capability(pktio, &appl_args->pktio[i].proto_stats_capa)) {
			ODPH_ERR("Reading pktio %s proto stats capa failed\n",
				 appl_args->pktio[i].name);
			ret = -1;
		}

		if (odp_pktio_close(pktio)) {
			ODPH_ERR("Closing pktio %s failed\n", appl_args->pktio[i].name);
			ret = -1;
		}

		if (ret)
			break;
	}

	if (odp_pool_destroy(pool)) {
		ODPH_ERR("Destroying pktio pool failed\n");
		return -1;
	}
	return ret;
}

static void print_pktio_capa(appl_args_t *appl_args)
{
	for (int i = 0; i < appl_args->num_pktio; i++) {
		odp_pktio_capability_t *capa = &appl_args->pktio[i].capa;

		printf("\n");
		printf("  PKTIO (%s)\n", appl_args->pktio[i].name);
		printf("    (in_mode:                      ODP_PKTIN_MODE_SCHED)\n");
		printf("    (out_mode:                     ODP_PKTOUT_MODE_DIRECT)\n");
		printf("    max_input_queues:              %u\n", capa->max_input_queues);
		printf("    min_input_queue_size:          %u\n", capa->min_input_queue_size);
		printf("    max_input_queue_size:          %u\n", capa->max_input_queue_size);
		printf("    max_output_queues:             %u\n", capa->max_output_queues);
		printf("    min_output_queue_size:         %u\n", capa->min_output_queue_size);
		printf("    max_output_queue_size:         %u\n", capa->max_output_queue_size);
		printf("    config.pktin:                  0x%" PRIx64 "\n",
		       capa->config.pktin.all_bits);
		printf("    config.pktout:                 0x%" PRIx64 "\n",
		       capa->config.pktout.all_bits);
		printf("    set_op:                        0x%" PRIx32 "\n", capa->set_op.all_bits);
		printf("    vector.supported:              %s\n",
		       support_level(capa->vector.supported));
		printf("    vector.max_size:               %u\n", capa->vector.max_size);
		printf("    vector.min_size:               %u\n", capa->vector.min_size);
		printf("    vector.max_tmo_ns:             %" PRIu64 " ns\n",
		       capa->vector.max_tmo_ns);
		printf("    vector.min_tmo_ns:             %" PRIu64 " ns\n",
		       capa->vector.min_tmo_ns);
		printf("    lso.max_profiles:              %u\n", capa->lso.max_profiles);
		printf("    lso.max_profiles_per_pktio:    %u\n", capa->lso.max_profiles_per_pktio);
		printf("    lso.max_packet_segments:       %u\n", capa->lso.max_packet_segments);
		printf("    lso.max_segments:              %u\n", capa->lso.max_segments);
		printf("    lso.max_payload_len:           %u B\n", capa->lso.max_payload_len);
		printf("    lso.max_payload_offset:        %u B\n", capa->lso.max_payload_offset);
		printf("    lso.mod_op.add_segment_num:    %u\n", capa->lso.mod_op.add_segment_num);
		printf("    lso.mod_op.add_payload_len:    %u\n", capa->lso.mod_op.add_payload_len);
		printf("    lso.mod_op.add_payload_offset: %u\n",
		       capa->lso.mod_op.add_payload_offset);
		printf("    lso.mod_op.write_bits:         %u\n", capa->lso.mod_op.write_bits);
		printf("    lso.max_num_custom:            %u\n", capa->lso.max_num_custom);
		printf("    lso.proto.custom:              %u\n", capa->lso.proto.custom);
		printf("    lso.proto.ipv4:                %u\n", capa->lso.proto.ipv4);
		printf("    lso.proto.ipv6:                %u\n", capa->lso.proto.ipv6);
		printf("    lso.proto.tcp_ipv4:            %u\n", capa->lso.proto.tcp_ipv4);
		printf("    lso.proto.tcp_ipv6:            %u\n", capa->lso.proto.tcp_ipv6);
		printf("    lso.proto.sctp_ipv4:           %u\n", capa->lso.proto.sctp_ipv4);
		printf("    lso.proto.sctp_ipv6:           %u\n", capa->lso.proto.sctp_ipv6);
		printf("    maxlen.equal:                  %i\n", capa->maxlen.equal);
		printf("    maxlen.min_input:              %u B\n", capa->maxlen.min_input);
		printf("    maxlen.max_input:              %u B\n", capa->maxlen.max_input);
		printf("    maxlen.min_output:             %u B\n", capa->maxlen.min_output);
		printf("    maxlen.max_output:             %u B\n", capa->maxlen.max_output);
		printf("    max_tx_aging_tmo_ns:           %" PRIu64 " ns\n",
		       capa->max_tx_aging_tmo_ns);
		printf("    tx_compl.queue_type_sched:     %i\n", capa->tx_compl.queue_type_sched);
		printf("    tx_compl.queue_type_plain:     %i\n", capa->tx_compl.queue_type_plain);
		printf("    tx_compl.mode_event:           %u\n", capa->tx_compl.mode_event);
		printf("    tx_compl.mode_poll:            %u\n", capa->tx_compl.mode_poll);
		printf("    tx_compl.max_compl_id:         %u\n", capa->tx_compl.max_compl_id);
		printf("    free_ctrl.dont_free:           %u\n", capa->free_ctrl.dont_free);
		printf("    reassembly.ip:                 %i\n", capa->reassembly.ip);
		printf("    reassembly.ipv4:               %i\n", capa->reassembly.ipv4);
		printf("    reassembly.ipv6:               %i\n", capa->reassembly.ipv6);
		printf("    reassembly.max_wait_time:      %" PRIu64 " ns\n",
		       capa->reassembly.max_wait_time);
		printf("    reassembly.max_num_frags:      %u\n", capa->reassembly.max_num_frags);
		printf("    stats.pktio:                   0x%" PRIx64 "\n",
		       capa->stats.pktio.all_counters);
		printf("    stats.pktin_queue:             0x%" PRIx64 "\n",
		       capa->stats.pktin_queue.all_counters);
		printf("    stats.pktout_queue:            0x%" PRIx64 "\n",
		       capa->stats.pktout_queue.all_counters);
		printf("    flow_control.pause_rx:         %u\n", capa->flow_control.pause_rx);
		printf("    flow_control.pfc_rx:           %u\n", capa->flow_control.pfc_rx);
		printf("    flow_control.pause_tx:         %u\n", capa->flow_control.pause_tx);
		printf("    flow_control.pfc_tx:           %u\n", capa->flow_control.pfc_tx);
	}
}

static void print_proto_stats_capa(appl_args_t *appl_args)
{
	for (int i = 0; i < appl_args->num_pktio; i++) {
		odp_proto_stats_capability_t *capa = &appl_args->pktio[i].proto_stats_capa;

		printf("\n");
		printf("  PROTO STATS (%s)\n", appl_args->pktio[i].name);
		printf("    tx.counters:          0x%" PRIx64 "\n", capa->tx.counters.all_bits);
		printf("    tx.oct_count0_adj:    %i\n", capa->tx.oct_count0_adj);
		printf("    tx.oct_count1_adj:    %i\n", capa->tx.oct_count1_adj);
	}
}

static int timer_capability(appl_args_t *appl_args)
{
	for (int i = 0; i < ODP_CLOCK_NUM_SRC; i++) {
		int ret;
		odp_timer_pool_t pool;
		odp_timer_pool_param_t params;
		odp_timer_capability_t *capa = &appl_args->timer.capa[appl_args->timer.num];
		odp_timer_pool_info_t *info = &appl_args->timer.pool_info[appl_args->timer.num];

		ret  = odp_timer_capability(i, capa);
		if (ret && i == ODP_CLOCK_DEFAULT) {
			ODPH_ERR("odp_timer_capability() failed for default clock source: %d\n",
				 ret);
			return -1;
		}
		if (ret == -1)
			continue;
		if (ret < -1) {
			ODPH_ERR("odp_timer_capability() for clock source %d failed: %d\n", i, ret);
			return -1;
		}

		odp_timer_pool_param_init(&params);
		params.clk_src    = i;
		params.res_ns     = capa->max_res.res_ns;
		params.min_tmo    = capa->max_res.min_tmo;
		params.max_tmo    = capa->max_res.max_tmo;
		params.num_timers = 1;

		pool = odp_timer_pool_create("timer_pool", &params);
		if (pool == ODP_TIMER_POOL_INVALID) {
			ODPH_ERR("odp_timer_pool_create() failed for clock source: %d\n", i);
			return -1;
		}

		if (odp_timer_pool_start_multi(&pool, 1) != 1) {
			ODPH_ERR("odp_timer_pool_start_multi() failed for clock source: %d\n", i);
			return -1;
		}

		ret = odp_timer_pool_info(pool, info);
		if (ret) {
			ODPH_ERR("odp_timer_pool_info() for clock source %d failed: %d\n", i, ret);
			return -1;
		}

		odp_timer_pool_destroy(pool);

		appl_args->timer.num++;
	}
	return 0;
}

static void print_timer_capa(appl_args_t *appl_args)
{
	for (int i = 0; i < appl_args->timer.num; i++) {
		odp_timer_capability_t *capa = &appl_args->timer.capa[i];
		odp_timer_pool_info_t *info = &appl_args->timer.pool_info[i];

		printf("\n");
		printf("  TIMER (SRC %d)\n", i);

		printf("    max_pools_combined:   %u\n", capa->max_pools_combined);
		printf("    max_pools:            %u\n", capa->max_pools);
		printf("    max_priority:         %u\n", capa->max_priority);
		printf("    max_timers:           %u\n", capa->max_timers);
		printf("    queue_type_sched:     %i\n", capa->queue_type_sched);
		printf("    queue_type_plain:     %i\n", capa->queue_type_plain);
		printf("    highest_res_ns:       %" PRIu64 " nsec\n", capa->highest_res_ns);
		printf("    maximum resolution\n");
		printf("      res_ns:             %" PRIu64 " nsec\n", capa->max_res.res_ns);
		printf("      res_hz:             %" PRIu64 " hz\n", capa->max_res.res_hz);
		printf("      min_tmo:            %" PRIu64 " nsec\n", capa->max_res.min_tmo);
		printf("      max_tmo:            %" PRIu64 " nsec\n", capa->max_res.max_tmo);
		printf("    maximum timeout\n");
		printf("      res_ns:             %" PRIu64 " nsec\n", capa->max_tmo.res_ns);
		printf("      res_hz:             %" PRIu64 " hz\n", capa->max_tmo.res_hz);
		printf("      min_tmo:            %" PRIu64 " nsec\n", capa->max_tmo.min_tmo);
		printf("      max_tmo:            %" PRIu64 " nsec\n", capa->max_tmo.max_tmo);
		printf("    periodic\n");
		printf("      max_pools:          %u\n", capa->periodic.max_pools);
		printf("      max_priority:       %u\n", capa->periodic.max_priority);
		printf("      max_timers:         %u\n", capa->periodic.max_timers);
		printf("      min_base_freq_hz:   %" PRIu64 " %" PRIu64 "/%" PRIu64 " Hz\n",
		       capa->periodic.min_base_freq_hz.integer,
		       capa->periodic.min_base_freq_hz.numer,
		       capa->periodic.min_base_freq_hz.denom);
		printf("      max_base_freq_hz:   %" PRIu64 " %" PRIu64 "/%" PRIu64 " Hz\n",
		       capa->periodic.max_base_freq_hz.integer,
		       capa->periodic.max_base_freq_hz.numer,
		       capa->periodic.max_base_freq_hz.denom);
		printf("    timer pool tick info (max_res)\n");
		printf("      freq:               %" PRIu64 " %" PRIu64 "/%" PRIu64 " Hz\n",
		       info->tick_info.freq.integer,
		       info->tick_info.freq.numer,
		       info->tick_info.freq.denom);
		printf("      nsec:               %" PRIu64 " %" PRIu64 "/%" PRIu64 " ns\n",
		       info->tick_info.nsec.integer,
		       info->tick_info.nsec.numer,
		       info->tick_info.nsec.denom);
		printf("      clk_cycle:          %" PRIu64 " %" PRIu64 "/%" PRIu64 " cycles\n",
		       info->tick_info.clk_cycle.integer,
		       info->tick_info.clk_cycle.numer,
		       info->tick_info.clk_cycle.denom);
	}
}

static void usage(void)
{
	printf("\n"
	       "System Information\n"
	       "\n"
	       "Usage: %s OPTIONS\n"
	       "  E.g. %s -i eth0\n"
	       "\n"
	       "Optional OPTIONS:\n"
	       "  -i, --interfaces   Ethernet interfaces for packet I/O, comma-separated, no\n"
	       "                     spaces.\n"
	       "  -h, --help         Display help and exit.\n"
	       "\n", PROG_NAME, PROG_NAME);
}

static void parse_interfaces(appl_args_t *config, const char *optarg)
{
	char *tmp_str = strdup(optarg), *tmp;

	if (tmp_str == NULL)
		return;

	tmp = strtok(tmp_str, ",");

	while (tmp && config->num_pktio < MAX_IFACES) {
		if (strlen(tmp) + 1 > MAX_NAME_LEN) {
			ODPH_ERR("Unable to store interface name (MAX_NAME_LEN=%d)\n",
				 MAX_NAME_LEN);
			exit(EXIT_FAILURE);
		}
		odph_strcpy(config->pktio[config->num_pktio].name, tmp, MAX_NAME_LEN);

		config->num_pktio++;

		tmp = strtok(NULL, ",");
	}

	free(tmp_str);
}

static void parse_args(int argc, char *argv[], appl_args_t *appl_args)
{
	int opt;
	static const struct option longopts[] = {
		{"interfaces", required_argument, NULL, 'i'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};
	static const char *shortopts =  "i:h";

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, NULL);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'i':
			parse_interfaces(appl_args, optarg);
			break;
		case 'h':
			usage();
			exit(EXIT_SUCCESS);
		case '?':
		default:
			usage();
			exit(EXIT_FAILURE);
		}
	}
}

int main(int argc, char **argv)
{
	odp_instance_t inst;
	int i, num_hp, num_hp_print;
	int num_ava, num_work, num_ctrl;
	odp_cpumask_t ava_mask, work_mask, ctrl_mask;
	odp_system_info_t sysinfo;
	odp_shm_capability_t shm_capa;
	odp_pool_capability_t pool_capa;
	odp_pool_ext_capability_t pool_ext_capa;
	odp_cls_capability_t cls_capa;
	odp_comp_capability_t comp_capa;
	odp_dma_capability_t dma_capa;
	odp_queue_capability_t queue_capa;
	odp_crypto_capability_t crypto_capa;
	odp_ipsec_capability_t ipsec_capa;
	odp_schedule_capability_t schedule_capa;
	odp_stash_capability_t stash_capa;
	odp_ml_capability_t ml_capa;
	appl_args_t appl_args;
	uint64_t huge_page[MAX_HUGE_PAGES];
	char ava_mask_str[ODP_CPUMASK_STR_SIZE];
	char work_mask_str[ODP_CPUMASK_STR_SIZE];
	char ctrl_mask_str[ODP_CPUMASK_STR_SIZE];
	int crypto_ret;
	int ipsec_ret;

	memset(&appl_args, 0, sizeof(appl_args_t));

	printf("\n");
	printf("ODP system info example\n");
	printf("***********************************************************\n");
	printf("\n");

	parse_args(argc, argv, &appl_args);

	if (odp_init_global(&inst, NULL, NULL)) {
		ODPH_ERR("Global init failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_init_local(inst, ODP_THREAD_CONTROL)) {
		ODPH_ERR("Local init failed.\n");
		exit(EXIT_FAILURE);
	}

	printf("\n");
	printf("odp_sys_info_print()\n");
	printf("***********************************************************\n");
	odp_sys_info_print();

	printf("\n");
	printf("odp_sys_config_print()\n");
	printf("***********************************************************\n");
	odp_sys_config_print();

	if (odp_system_info(&sysinfo)) {
		ODPH_ERR("system info call failed\n");
		exit(EXIT_FAILURE);
	}

	memset(ava_mask_str, 0, ODP_CPUMASK_STR_SIZE);
	num_ava = odp_cpumask_all_available(&ava_mask);
	odp_cpumask_to_str(&ava_mask, ava_mask_str, ODP_CPUMASK_STR_SIZE);

	memset(work_mask_str, 0, ODP_CPUMASK_STR_SIZE);
	num_work = odp_cpumask_default_worker(&work_mask, 0);
	odp_cpumask_to_str(&work_mask, work_mask_str, ODP_CPUMASK_STR_SIZE);

	memset(ctrl_mask_str, 0, ODP_CPUMASK_STR_SIZE);
	num_ctrl = odp_cpumask_default_control(&ctrl_mask, 0);
	odp_cpumask_to_str(&ctrl_mask, ctrl_mask_str, ODP_CPUMASK_STR_SIZE);

	num_hp = odp_sys_huge_page_size_all(huge_page, MAX_HUGE_PAGES);

	num_hp_print = num_hp;
	if (num_hp_print > MAX_HUGE_PAGES)
		num_hp_print = MAX_HUGE_PAGES;

	if (odp_shm_capability(&shm_capa)) {
		ODPH_ERR("shm capability failed\n");
		exit(EXIT_FAILURE);
	}

	if (odp_pool_capability(&pool_capa)) {
		ODPH_ERR("pool capability failed\n");
		exit(EXIT_FAILURE);
	}

	if (odp_pool_ext_capability(ODP_POOL_PACKET, &pool_ext_capa)) {
		ODPH_ERR("external packet pool capability failed\n");
		exit(EXIT_FAILURE);
	}

	if (pktio_capability(&appl_args)) {
		ODPH_ERR("pktio capability failed\n");
		exit(EXIT_FAILURE);
	}

	if (odp_cls_capability(&cls_capa)) {
		ODPH_ERR("classifier capability failed\n");
		exit(EXIT_FAILURE);
	}

	if (odp_comp_capability(&comp_capa)) {
		ODPH_ERR("compression capability failed\n");
		exit(EXIT_FAILURE);
	}

	if (odp_dma_capability(&dma_capa)) {
		ODPH_ERR("dma capability failed\n");
		exit(EXIT_FAILURE);
	}

	if (odp_queue_capability(&queue_capa)) {
		ODPH_ERR("queue capability failed\n");
		exit(EXIT_FAILURE);
	}

	if (odp_schedule_capability(&schedule_capa)) {
		ODPH_ERR("schedule capability failed\n");
		exit(EXIT_FAILURE);
	}

	if (odp_stash_capability(&stash_capa, ODP_STASH_TYPE_DEFAULT)) {
		ODPH_ERR("stash capability failed\n");
		exit(EXIT_FAILURE);
	}

	if (timer_capability(&appl_args)) {
		ODPH_ERR("timer capability failed\n");
		exit(EXIT_FAILURE);
	}

	if (odp_ml_capability(&ml_capa)) {
		ODPH_ERR("ml capability failed\n");
		exit(EXIT_FAILURE);
	}

	crypto_ret = odp_crypto_capability(&crypto_capa);
	if (crypto_ret < 0)
		ODPH_ERR("crypto capability failed\n");

	ipsec_ret = odp_ipsec_capability(&ipsec_capa);
	if (ipsec_ret < 0)
		ODPH_ERR("IPsec capability failed\n");

	printf("\n");
	printf("S Y S T E M    I N F O R M A T I O N\n");
	printf("***********************************************************\n");
	printf("\n");
	printf("  ODP API version:        %s\n", odp_version_api_str());
	printf("  ODP impl name:          %s\n", odp_version_impl_name());
	printf("  ODP impl details:       %s\n", odp_version_impl_str());
	printf("  CPU model:              %s\n", odp_cpu_model_str());
	printf("  CPU arch:               %s\n", cpu_arch_name(&sysinfo));
	printf("  CPU ISA version:        %s\n", cpu_arch_isa(&sysinfo, 0));
	printf("  SW ISA version:         %s\n", cpu_arch_isa(&sysinfo, 1));
	printf("  CPU max freq:           %" PRIu64 " hz\n", odp_cpu_hz_max());
	printf("  Current CPU:            %i\n", odp_cpu_id());
	printf("  Current CPU freq:       %" PRIu64 " hz\n", odp_cpu_hz());
	printf("  CPU count:              %i\n", odp_cpu_count());
	printf("  CPU available num:      %i\n", num_ava);
	printf("  CPU available mask:     %s\n", ava_mask_str);
	printf("  CPU worker num:         %i\n", num_work);
	printf("  CPU worker mask:        %s\n", work_mask_str);
	printf("  CPU control num:        %i\n", num_ctrl);
	printf("  CPU control mask:       %s\n", ctrl_mask_str);
	printf("  Max threads (define):   %i\n", ODP_THREAD_COUNT_MAX);
	printf("  Max threads:            %i\n", odp_thread_count_max());
	printf("  Byte order:             %s (%i / %i)\n",
	       ODP_BYTE_ORDER == ODP_BIG_ENDIAN ? "big" : "little",
	       ODP_BIG_ENDIAN, ODP_LITTLE_ENDIAN);
	printf("  Bitfield order:         %s (%i / %i)\n",
	       ODP_BITFIELD_ORDER == ODP_BIG_ENDIAN_BITFIELD ?
	       "big" : "little",
	       ODP_BIG_ENDIAN_BITFIELD, ODP_LITTLE_ENDIAN_BITFIELD);
	printf("  Cache line size:        %i B\n", odp_sys_cache_line_size());
	printf("  Page size:              %" PRIu64 " kB\n", odp_sys_page_size() / KB);
	printf("  Default huge page size: %" PRIu64 " kB\n", odp_sys_huge_page_size() / KB);
	printf("  Num huge page sizes:    %i\n", num_hp);

	for (i = 0; i < num_hp_print; i++)
		printf("  Huge page size [%i]:     %" PRIu64 " kB\n",
		       i, huge_page[i] / KB);

	printf("\n");
	printf("  SHM\n");
	printf("    max_blocks:           %u\n", shm_capa.max_blocks);
	printf("    max_size:             %" PRIu64 " MB\n", shm_capa.max_size / MB);
	printf("    max_align:            %" PRIu64 " B\n", shm_capa.max_align);
	printf("    flags:                0x%x: %s%s%s%s%s%s\n", shm_capa.flags,
	       (shm_capa.flags & ODP_SHM_PROC) ? "PROC " : "",
	       (shm_capa.flags & ODP_SHM_SINGLE_VA) ? "SINGLE_VA " : "",
	       (shm_capa.flags & ODP_SHM_EXPORT) ? "EXPORT " : "",
	       (shm_capa.flags & ODP_SHM_HP) ? "HP " : "",
	       (shm_capa.flags & ODP_SHM_HW_ACCESS) ? "HW_ACCESS " : "",
	       (shm_capa.flags & ODP_SHM_NO_HP) ? "NO_HP " : "");

	print_atomic_lock_free();

	printf("\n");
	printf("  POOL\n");
	printf("    max_pools:                %u\n", pool_capa.max_pools);
	printf("    buf.max_pools:            %u\n", pool_capa.buf.max_pools);
	printf("    buf.max_align:            %u B\n", pool_capa.buf.max_align);
	printf("    buf.max_size:             %u kB\n", pool_capa.buf.max_size / KB);
	printf("    buf.max_num:              %u\n", pool_capa.buf.max_num);
	printf("    buf.max_uarea_size:       %u B\n", pool_capa.buf.max_uarea_size);
	printf("    buf.uarea_persistence:    %i\n", pool_capa.buf.uarea_persistence);
	printf("    buf.min_cache_size:       %u\n", pool_capa.buf.min_cache_size);
	printf("    buf.max_cache_size:       %u\n", pool_capa.buf.max_cache_size);
	printf("    buf.stats:                0x%" PRIx64 "\n", pool_capa.buf.stats.all);
	printf("    pkt.max_pools:            %u\n", pool_capa.pkt.max_pools);
	printf("    pkt.max_len:              %u kB\n", pool_capa.pkt.max_len / KB);
	printf("    pkt.max_num:              %u\n", pool_capa.pkt.max_num);
	printf("    pkt.max_align:            %u B\n", pool_capa.pkt.max_align);
	printf("    pkt.min_headroom:         %u B\n", pool_capa.pkt.min_headroom);
	printf("    pkt.max_headroom:         %u B\n", pool_capa.pkt.max_headroom);
	printf("    pkt.min_tailroom:         %u B\n", pool_capa.pkt.min_tailroom);
	printf("    pkt.max_segs_per_pkt:     %u\n", pool_capa.pkt.max_segs_per_pkt);
	printf("    pkt.min_seg_len:          %u B\n", pool_capa.pkt.min_seg_len);
	printf("    pkt.max_seg_len:          %u B\n", pool_capa.pkt.max_seg_len);
	printf("    pkt.max_uarea_size:       %u B\n", pool_capa.pkt.max_uarea_size);
	printf("    pkt.uarea_persistence:    %i\n", pool_capa.pkt.uarea_persistence);
	printf("    pkt.max_num_subparam:     %u\n", pool_capa.pkt.max_num_subparam);
	printf("    pkt.min_cache_size:       %u\n", pool_capa.pkt.min_cache_size);
	printf("    pkt.max_cache_size:       %u\n", pool_capa.pkt.max_cache_size);
	printf("    pkt.stats:                0x%" PRIx64 "\n", pool_capa.pkt.stats.all);
	printf("    tmo.max_pools:            %u\n", pool_capa.tmo.max_pools);
	printf("    tmo.max_num:              %u\n", pool_capa.tmo.max_num);
	printf("    tmo.max_uarea_size:       %u B\n", pool_capa.tmo.max_uarea_size);
	printf("    tmo.uarea_persistence:    %i\n", pool_capa.tmo.uarea_persistence);
	printf("    tmo.min_cache_size:       %u\n", pool_capa.tmo.min_cache_size);
	printf("    tmo.max_cache_size:       %u\n", pool_capa.tmo.max_cache_size);
	printf("    tmo.stats:                0x%" PRIx64 "\n", pool_capa.tmo.stats.all);
	printf("    vector.max_pools:         %u\n", pool_capa.vector.max_pools);
	printf("    vector.max_num:           %u\n", pool_capa.vector.max_num);
	printf("    vector.max_size:          %u\n", pool_capa.vector.max_size);
	printf("    vector.max_uarea_size:    %u B\n", pool_capa.vector.max_uarea_size);
	printf("    vector.uarea_persistence: %i\n", pool_capa.vector.uarea_persistence);
	printf("    vector.min_cache_size:    %u\n", pool_capa.vector.min_cache_size);
	printf("    vector.max_cache_size:    %u\n", pool_capa.vector.max_cache_size);
	printf("    vector.stats:             0x%" PRIx64 "\n", pool_capa.vector.stats.all);
#define capa pool_capa.event_vector
	printf("    event_vector.max_pools:         %u\n", capa.max_pools);
	printf("    event_vector.max_num:           %u\n", capa.max_num);
	printf("    event_vector.max_size:          %u\n", capa.max_size);
	printf("    event_vector.max_uarea_size:    %u B\n", capa.max_uarea_size);
	printf("    event_vector.uarea_persistence: %i\n", capa.uarea_persistence);
	printf("    event_vector.min_cache_size:    %u\n", capa.min_cache_size);
	printf("    event_vector.max_cache_size:    %u\n", capa.max_cache_size);
	printf("    event_vector.stats:             0x%" PRIx64 "\n", capa.stats.all);
#undef capa

	printf("\n");
	printf("  POOL EXT (pkt)\n");
	printf("    max_pools:             %u\n", pool_ext_capa.max_pools);
	if (pool_ext_capa.max_pools) {
		printf("    min_cache_size:        %u\n", pool_ext_capa.min_cache_size);
		printf("    max_cache_size:        %u\n", pool_ext_capa.max_cache_size);
		printf("    stats:                 0x%" PRIx64 "\n", pool_ext_capa.stats.all);
		printf("    pkt.max_num_buf:       %u\n", pool_ext_capa.pkt.max_num_buf);
		printf("    pkt.max_buf_size:      %u B\n", pool_ext_capa.pkt.max_buf_size);
		printf("    pkt.odp_header_size:   %u B\n", pool_ext_capa.pkt.odp_header_size);
		printf("    pkt.odp_trailer_size:  %u B\n", pool_ext_capa.pkt.odp_trailer_size);
		printf("    pkt.min_mem_align:     %u B\n", pool_ext_capa.pkt.min_mem_align);
		printf("    pkt.min_buf_align:     %u B\n", pool_ext_capa.pkt.min_buf_align);
		printf("    pkt.min_head_align:    %u B\n", pool_ext_capa.pkt.min_head_align);
		printf("    pkt.buf_size_aligned:  %u\n", pool_ext_capa.pkt.buf_size_aligned);
		printf("    pkt.max_headroom:      %u B\n", pool_ext_capa.pkt.max_headroom);
		printf("    pkt.max_headroom_size: %u B\n", pool_ext_capa.pkt.max_headroom_size);
		printf("    pkt.max_segs_per_pkt:  %u\n", pool_ext_capa.pkt.max_segs_per_pkt);
		printf("    pkt.max_uarea_size:    %u B\n", pool_ext_capa.pkt.max_uarea_size);
		printf("    pkt.uarea_persistence: %i\n", pool_ext_capa.pkt.uarea_persistence);
	}

	print_pktio_capa(&appl_args);

	print_proto_stats_capa(&appl_args);

	printf("\n");
	printf("  CLASSIFIER\n");
	printf("    supported_terms:        0x%" PRIx64 "\n", cls_capa.supported_terms.all_bits);
	printf("    max_pmr:                %u\n", cls_capa.max_pmr);
	printf("    max_pmr_per_cos:        %u\n", cls_capa.max_pmr_per_cos);
	printf("    max_terms_per_pmr:      %u\n", cls_capa.max_terms_per_pmr);
	printf("    max_cos:                %u\n", cls_capa.max_cos);
	printf("    max_hash_queues:        %u\n", cls_capa.max_hash_queues);
	printf("    hash_protocols:         0x%x\n", cls_capa.hash_protocols.all_bits);
	printf("    pmr_range_supported:    %i\n", cls_capa.pmr_range_supported);
	printf("    random_early_detection: %s\n", support_level(cls_capa.random_early_detection));
	printf("    threshold_red:          0x%" PRIx8 "\n", cls_capa.threshold_red.all_bits);
	printf("    back_pressure:          %s\n", support_level(cls_capa.back_pressure));
	printf("    threshold_bp:           0x%" PRIx8 "\n", cls_capa.threshold_bp.all_bits);
	printf("    max_mark:               %" PRIu64 "\n", cls_capa.max_mark);
	printf("    stats.queue:            0x%" PRIx64 "\n", cls_capa.stats.queue.all_counters);
	#define aep_type cls_capa.aggr.enq_profile_type
	printf("    aggr.enq_profile_type.ipv4_frag: %u\n", aep_type.ipv4_frag);
	printf("    aggr.enq_profile_type.ipv6_frag: %u\n", aep_type.ipv6_frag);
	printf("    aggr.enq_profile_type.custom:    %u\n", aep_type.custom);
	#undef aep_type

	printf("\n");
	printf("  COMPRESSION\n");
	printf("    max_sessions:         %u\n", comp_capa.max_sessions);
	printf("    compl_algos:          0x%x\n", comp_capa.comp_algos.all_bits);
	printf("    hash_algos:           0x%x\n", comp_capa.hash_algos.all_bits);
	printf("    sync support:         %i\n", comp_capa.sync);
	printf("    async support:        %i\n", comp_capa.async);

	printf("\n");
	printf("  DMA\n");
	printf("    max_sessions:           %u\n", dma_capa.max_sessions);
	printf("    max_transfers:          %u\n", dma_capa.max_transfers);
	printf("    max_src_segs:           %u\n", dma_capa.max_src_segs);
	printf("    max_dst_segs:           %u\n", dma_capa.max_dst_segs);
	printf("    max_segs:               %u\n", dma_capa.max_segs);
	printf("    max_seg_len:            %u B\n", dma_capa.max_seg_len);
	printf("    compl_mode_mask:        0x%x\n", dma_capa.compl_mode_mask);
	printf("    queue_type_sched:       %i\n", dma_capa.queue_type_sched);
	printf("    queue_type_plain:       %i\n", dma_capa.queue_type_plain);
	printf("    src_seg_free:           %i\n", dma_capa.src_seg_free);
	printf("    dst_seg_alloc:          %i\n", dma_capa.dst_seg_alloc);
	printf("    pool.max_pools:         %u\n", dma_capa.pool.max_pools);
	printf("    pool.max_num:           %u\n", dma_capa.pool.max_num);
	printf("    pool.max_uarea_size:    %u B\n", dma_capa.pool.max_uarea_size);
	printf("    pool.uarea_persistence: %u\n", dma_capa.pool.uarea_persistence);
	printf("    pool.min_cache_size:    %u\n", dma_capa.pool.min_cache_size);
	printf("    pool.max_cache_size:    %u\n", dma_capa.pool.max_cache_size);

	printf("\n");
	printf("  QUEUE\n");
	printf("    max queues:           %u\n", queue_capa.max_queues);
	printf("    plain.max_num:        %u\n", queue_capa.plain.max_num);
	printf("    plain.max_size:       %u\n", queue_capa.plain.max_size);
	printf("    plain.lf.max_num:     %u\n", queue_capa.plain.lockfree.max_num);
	printf("    plain.lf.max_size:    %u\n", queue_capa.plain.lockfree.max_size);
	printf("    plain.wf.max_num:     %u\n", queue_capa.plain.waitfree.max_num);
	printf("    plain.wf.max_size:    %u\n", queue_capa.plain.waitfree.max_size);
	printf("    plain.aggr.max_num:   %u\n", queue_capa.plain.aggr.max_num);
	printf("    plain.aggr.max_num_per_queue: %u\n", queue_capa.plain.aggr.max_num_per_queue);
	printf("    plain.aggr.max_size:  %u\n", queue_capa.plain.aggr.max_size);
	printf("    plain.aggr.min_size:  %u\n", queue_capa.plain.aggr.min_size);
	printf("    plain.aggr.max_tmo_ns: %" PRIu64 "\n", queue_capa.plain.aggr.max_tmo_ns);
	printf("    plain.aggr.min_tmo_ns: %" PRIu64 "\n", queue_capa.plain.aggr.min_tmo_ns);

	printf("\n");
	printf("  SCHEDULER\n");
	printf("    max_ordered_locks:    %u\n", schedule_capa.max_ordered_locks);
	printf("    max_groups:           %u\n", schedule_capa.max_groups);
	printf("    max_prios:            %u\n", schedule_capa.max_prios);
	printf("    max_queues:           %u\n", schedule_capa.max_queues);
	printf("    max_queue_size:       %u\n", schedule_capa.max_queue_size);
	printf("    max_flow_id:          %u\n", schedule_capa.max_flow_id);
	printf("    lockfree_queues:      %s\n", support_level(schedule_capa.lockfree_queues));
	printf("    waitfree_queues:      %s\n", support_level(schedule_capa.waitfree_queues));
	printf("    order_wait:           %s\n", support_level(schedule_capa.order_wait));
	printf("    aggr.max_num:         %u\n", schedule_capa.aggr.max_num);
	printf("    aggr.max_num_per_queue: %u\n", schedule_capa.aggr.max_num_per_queue);
	printf("    aggr.max_size:        %u\n", schedule_capa.aggr.max_size);
	printf("    aggr.min_size:        %u\n", schedule_capa.aggr.min_size);
	printf("    aggr.max_tmo_ns:      %" PRIu64 "\n", schedule_capa.aggr.max_tmo_ns);
	printf("    aggr.min_tmo_ns:      %" PRIu64 "\n", schedule_capa.aggr.min_tmo_ns);

	printf("\n");
	printf("  STASH\n");
	printf("    max_stashes_any_type: %u\n", stash_capa.max_stashes_any_type);
	printf("    max_stashes:          %u\n", stash_capa.max_stashes);
	printf("    max_num_obj:          %" PRIu64 "\n", stash_capa.max_num_obj);
	printf("    max_num.u8:           %" PRIu64 "\n", stash_capa.max_num.u8);
	printf("    max_num.u16:          %" PRIu64 "\n", stash_capa.max_num.u16);
	printf("    max_num.u32:          %" PRIu64 "\n", stash_capa.max_num.u32);
	printf("    max_num.u64:          %" PRIu64 "\n", stash_capa.max_num.u64);
	printf("    max_num.u128:         %" PRIu64 "\n", stash_capa.max_num.u128);
	printf("    max_num.max_obj_size: %" PRIu64 "\n", stash_capa.max_num.max_obj_size);
	printf("    max_obj_size:         %u B\n", stash_capa.max_obj_size);
	printf("    max_cache_size:       %u\n", stash_capa.max_cache_size);
	printf("    max_get_batch:        %u\n", stash_capa.max_get_batch);
	printf("    max_put_batch:        %u\n", stash_capa.max_put_batch);
	printf("    stats:                0x%" PRIx64 "\n", stash_capa.stats.all);

	printf("\n");
	printf("  ML\n");
	printf("    max_models:             %u\n", ml_capa.max_models);
	printf("    max_models_loaded:      %u\n", ml_capa.max_models_loaded);
	printf("    max_model_size:         %" PRIu64 "B\n", ml_capa.max_model_size);
	printf("    max_compl_id:           %u\n", ml_capa.max_compl_id);
	printf("    max_inputs:             %u\n", ml_capa.max_inputs);
	printf("    max_outputs:            %u\n", ml_capa.max_outputs);
	printf("    max_segs_per_input:     %u\n", ml_capa.max_segs_per_input);
	printf("    max_segs_per_output:    %u\n", ml_capa.max_segs_per_output);
	printf("    min_input_align:        %u\n", ml_capa.min_input_align);
	printf("    min_output_align:       %u\n", ml_capa.min_output_align);
	printf("    packed_input_data:      %u\n", ml_capa.packed_input_data);
	printf("    packed_output_data:     %u\n", ml_capa.packed_output_data);
	printf("    load.compl_mode_mask:   0x%x\n", ml_capa.load.compl_mode_mask);
	printf("    load.compl_queue_plain: %i\n", ml_capa.load.compl_queue_plain);
	printf("    load.compl_queue_sched: %i\n", ml_capa.load.compl_queue_sched);
	printf("    run.compl_mode_mask:    0x%x\n", ml_capa.run.compl_mode_mask);
	printf("    run.compl_queue_plain:  %i\n", ml_capa.run.compl_queue_plain);
	printf("    run.compl_queue_sched:  %i\n", ml_capa.run.compl_queue_sched);
	printf("    pool.max_pools:         %u\n", ml_capa.pool.max_pools);
	printf("    pool.max_num:           %u\n", ml_capa.pool.max_num);
	printf("    pool.max_uarea_size:    %u B\n", ml_capa.pool.max_uarea_size);
	printf("    pool.uarea_persistence: %u\n", ml_capa.pool.uarea_persistence);
	printf("    pool.min_cache_size:    %u\n", ml_capa.pool.min_cache_size);
	printf("    pool.max_cache_size:    %u\n", ml_capa.pool.max_cache_size);

	print_timer_capa(&appl_args);

	if (crypto_ret == 0) {
		printf("\n");
		printf("  CRYPTO\n");
		printf("    max sessions:           %u\n", crypto_capa.max_sessions);
		printf("    sync mode support:      %s\n", support_level(crypto_capa.sync_mode));
		printf("    async mode support:     %s\n", support_level(crypto_capa.async_mode));
		printf("    queue_type_sched:       %i\n", crypto_capa.queue_type_sched);
		printf("    queue_type_plain:       %i\n", crypto_capa.queue_type_plain);
		printf("    cipher algorithms:      ");
		foreach_cipher(crypto_capa.ciphers, print_cipher);
		printf("\n");
		foreach_cipher(crypto_capa.ciphers, print_cipher_capa);
		printf("    cipher algorithms (HW): ");
		foreach_cipher(crypto_capa.hw_ciphers, print_cipher);
		printf("\n");
		foreach_cipher(crypto_capa.hw_ciphers, print_cipher_capa);
		printf("    auth algorithms:        ");
		foreach_auth(crypto_capa.auths, print_auth);
		printf("\n");
		foreach_auth(crypto_capa.auths, print_auth_capa);
		printf("    auth algorithms (HW):   ");
		foreach_auth(crypto_capa.hw_auths, print_auth);
		printf("\n");
		foreach_auth(crypto_capa.hw_auths, print_auth_capa);
	}

	if (ipsec_ret == 0) {
		printf("\n");
		printf("  IPSEC\n");
		printf("    max SAs:                      %u\n", ipsec_capa.max_num_sa);
		printf("    sync mode support:            %s\n",
		       support_level(ipsec_capa.op_mode_sync));
		printf("    async mode support:           %s\n",
		       support_level(ipsec_capa.op_mode_async));
		printf("    inline inbound mode support:  %s\n",
		       support_level(ipsec_capa.op_mode_inline_in));
		printf("    inline outbound mode support: %s\n",
		       support_level(ipsec_capa.op_mode_inline_out));
		printf("    AH support:                   %s\n",
		       support_level(ipsec_capa.proto_ah));
		printf("    post-IPsec fragmentation:     %s\n",
		       support_level(ipsec_capa.frag_after));
		printf("    pre-IPsec fragmentation:      %s\n",
		       support_level(ipsec_capa.frag_before));
		printf("    post-IPsec classification:    %s\n",
		       support_level(ipsec_capa.pipeline_cls));
		printf("    retaining outer headers:      %s\n",
		       support_level(ipsec_capa.retain_header));
		printf("    inbound checksum offload support:\n");
		printf("      IPv4 header checksum:       %s\n",
		       support_level(ipsec_capa.chksums_in.chksum.ipv4));
		printf("      UDP checksum:               %s\n",
		       support_level(ipsec_capa.chksums_in.chksum.udp));
		printf("      TCP checksum:               %s\n",
		       support_level(ipsec_capa.chksums_in.chksum.tcp));
		printf("      SCTP checksum:              %s\n",
		       support_level(ipsec_capa.chksums_in.chksum.sctp));
		printf("    max destination CoSes:        %u\n", ipsec_capa.max_cls_cos);
		printf("    max destination queues:       %u\n", ipsec_capa.max_queues);
		printf("    queue_type_sched:             %i\n", ipsec_capa.queue_type_sched);
		printf("    queue_type_plain:             %i\n", ipsec_capa.queue_type_plain);
		printf("    vector support:               %s\n",
		       support_level(ipsec_capa.vector.supported));
		printf("      min_size:                   %u\n", ipsec_capa.vector.min_size);
		printf("      max_size:                   %u\n", ipsec_capa.vector.max_size);
		printf("      min_tmo_ns:                 %" PRIu64 " ns\n",
		       ipsec_capa.vector.min_tmo_ns);
		printf("      max_tmo_ns:                 %" PRIu64 " ns\n",
		       ipsec_capa.vector.max_tmo_ns);
		printf("    max anti-replay window size:  %u\n",
		       ipsec_capa.max_antireplay_ws);
		printf("    inline TM pipelining:         %s\n",
		       support_level(ipsec_capa.inline_ipsec_tm));
		printf("    testing capabilities:\n");
		printf("      sa_operations.seq_num:      %i\n",
		       ipsec_capa.test.sa_operations.seq_num);
		printf("      sa_operations.antireplay_window_top: %i\n",
		       ipsec_capa.test.sa_operations.antireplay_window_top);
		printf("    post-IPsec reassembly support:\n");
		printf("      ip:                         %i\n", ipsec_capa.reassembly.ip);
		printf("      ipv4:                       %i\n", ipsec_capa.reassembly.ipv4);
		printf("      ipv6:                       %i\n", ipsec_capa.reassembly.ipv6);
		printf("      max_wait_time:              %" PRIu64 "\n",
		       ipsec_capa.reassembly.max_wait_time);
		printf("      max_num_frags:              %" PRIu16 "\n",
		       ipsec_capa.reassembly.max_num_frags);
		printf("    reass_async:                  %i\n", ipsec_capa.reass_async);
		printf("    reass_inline:                 %i\n", ipsec_capa.reass_inline);
		printf("    cipher algorithms:            ");
		foreach_cipher(ipsec_capa.ciphers, print_cipher);
		printf("\n");
		printf("    auth algorithms:              ");
		foreach_auth(ipsec_capa.auths, print_auth);
		printf("\n");
	}

	printf("\n");
	printf("  SHM MEMORY BLOCKS:\n");
	odp_shm_print_all();

	printf("\n");
	printf("***********************************************************\n");
	printf("\n");

	if (odp_term_local()) {
		ODPH_ERR("Local term failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_global(inst)) {
		ODPH_ERR("Global term failed.\n");
		exit(EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}
