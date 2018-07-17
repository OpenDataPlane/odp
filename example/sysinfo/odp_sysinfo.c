/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include <odp_api.h>

#define KB              1024
#define MB              (1024 * 1024)
#define MAX_HUGE_PAGES  32

static const char *support_level(odp_support_t support)
{
	switch (support) {
	case ODP_SUPPORT_NO: return "no";
	case ODP_SUPPORT_YES: return "yes";
	case ODP_SUPPORT_PREFERRED: return "yes, preferred";
	default: return "UNKNOWN";
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
	case ODP_CIPHER_ALG_AES_CBC:
		return "aes_cbc";
	case ODP_CIPHER_ALG_AES_CTR:
		return "aes_ctr";
	case ODP_CIPHER_ALG_AES_GCM:
		return "aes_gcm";
	case ODP_CIPHER_ALG_AES_CCM:
		return "aes_ccm";
	case ODP_CIPHER_ALG_CHACHA20_POLY1305:
		return "chacha20_poly1305";
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
	case ODP_AUTH_ALG_SHA256_HMAC:
		return "sha256_hmac";
	case ODP_AUTH_ALG_SHA384_HMAC:
		return "sha384_hmac";
	case ODP_AUTH_ALG_SHA512_HMAC:
		return "sha512_hmac";
	case ODP_AUTH_ALG_AES_XCBC_MAC:
		return "aes_xcbc_mac";
	case ODP_AUTH_ALG_AES_GCM:
		return "aes_gcm";
	case ODP_AUTH_ALG_AES_GMAC:
		return "aes_gmac";
	case ODP_AUTH_ALG_AES_CCM:
		return "aes_ccm";
	case ODP_AUTH_ALG_AES_CMAC:
		return "aes_cmac";
	case ODP_AUTH_ALG_CHACHA20_POLY1305:
		return "chacha20_poly1305";
	default:
		return "Unknown";
	}
}

static void print_cipher_algos(odp_crypto_cipher_algos_t ciphers)
{
	if (ciphers.bit.null)
		printf("%s ", cipher_alg_name(ODP_CIPHER_ALG_NULL));
	if (ciphers.bit.des)
		printf("%s ", cipher_alg_name(ODP_CIPHER_ALG_DES));
	if (ciphers.bit.trides_cbc)
		printf("%s ", cipher_alg_name(ODP_CIPHER_ALG_3DES_CBC));
	if (ciphers.bit.aes_cbc)
		printf("%s ", cipher_alg_name(ODP_CIPHER_ALG_AES_CBC));
	if (ciphers.bit.aes_ctr)
		printf("%s ", cipher_alg_name(ODP_CIPHER_ALG_AES_CTR));
	if (ciphers.bit.aes_gcm)
		printf("%s ", cipher_alg_name(ODP_CIPHER_ALG_AES_GCM));
	if (ciphers.bit.aes_ccm)
		printf("%s ", cipher_alg_name(ODP_CIPHER_ALG_AES_CCM));
	if (ciphers.bit.chacha20_poly1305)
		printf("%s ",
		       cipher_alg_name(ODP_CIPHER_ALG_CHACHA20_POLY1305));
}

static void print_auth_algos(odp_crypto_auth_algos_t auths)
{
	if (auths.bit.null)
		printf("%s ", auth_alg_name(ODP_AUTH_ALG_NULL));
	if (auths.bit.md5_hmac)
		printf("%s ", auth_alg_name(ODP_AUTH_ALG_MD5_HMAC));
	if (auths.bit.sha1_hmac)
		printf("%s ", auth_alg_name(ODP_AUTH_ALG_SHA1_HMAC));
	if (auths.bit.sha256_hmac)
		printf("%s ", auth_alg_name(ODP_AUTH_ALG_SHA256_HMAC));
	if (auths.bit.sha384_hmac)
		printf("%s ", auth_alg_name(ODP_AUTH_ALG_SHA384_HMAC));
	if (auths.bit.sha512_hmac)
		printf("%s ", auth_alg_name(ODP_AUTH_ALG_SHA512_HMAC));
	if (auths.bit.aes_gcm)
		printf("%s ", auth_alg_name(ODP_AUTH_ALG_AES_GCM));
	if (auths.bit.aes_gmac)
		printf("%s ", auth_alg_name(ODP_AUTH_ALG_AES_GMAC));
	if (auths.bit.aes_ccm)
		printf("%s ", auth_alg_name(ODP_AUTH_ALG_AES_CCM));
	if (auths.bit.aes_cmac)
		printf("%s ", auth_alg_name(ODP_AUTH_ALG_AES_CMAC));
	if (auths.bit.aes_xcbc_mac)
		printf("%s ", auth_alg_name(ODP_AUTH_ALG_AES_XCBC_MAC));
	if (auths.bit.chacha20_poly1305)
		printf("%s ", auth_alg_name(ODP_AUTH_ALG_CHACHA20_POLY1305));
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

static void print_cipher_caps(odp_crypto_cipher_algos_t ciphers)
{
	if (ciphers.bit.null)
		print_cipher_capa(ODP_CIPHER_ALG_NULL);
	if (ciphers.bit.des)
		print_cipher_capa(ODP_CIPHER_ALG_DES);
	if (ciphers.bit.trides_cbc)
		print_cipher_capa(ODP_CIPHER_ALG_3DES_CBC);
	if (ciphers.bit.aes_cbc)
		print_cipher_capa(ODP_CIPHER_ALG_AES_CBC);
	if (ciphers.bit.aes_ctr)
		print_cipher_capa(ODP_CIPHER_ALG_AES_CTR);
	if (ciphers.bit.aes_gcm)
		print_cipher_capa(ODP_CIPHER_ALG_AES_GCM);
	if (ciphers.bit.aes_ccm)
		print_cipher_capa(ODP_CIPHER_ALG_AES_CCM);
	if (ciphers.bit.chacha20_poly1305)
		print_cipher_capa(ODP_CIPHER_ALG_CHACHA20_POLY1305);
}

static void print_auth_caps(odp_crypto_auth_algos_t auths)
{
	if (auths.bit.null)
		print_auth_capa(ODP_AUTH_ALG_NULL);
	if (auths.bit.md5_hmac)
		print_auth_capa(ODP_AUTH_ALG_MD5_HMAC);
	if (auths.bit.sha1_hmac)
		print_auth_capa(ODP_AUTH_ALG_SHA1_HMAC);
	if (auths.bit.sha256_hmac)
		print_auth_capa(ODP_AUTH_ALG_SHA256_HMAC);
	if (auths.bit.sha384_hmac)
		print_auth_capa(ODP_AUTH_ALG_SHA384_HMAC);
	if (auths.bit.sha512_hmac)
		print_auth_capa(ODP_AUTH_ALG_SHA512_HMAC);
	if (auths.bit.aes_gcm)
		print_auth_capa(ODP_AUTH_ALG_AES_GCM);
	if (auths.bit.aes_gmac)
		print_auth_capa(ODP_AUTH_ALG_AES_GMAC);
	if (auths.bit.aes_ccm)
		print_auth_capa(ODP_AUTH_ALG_AES_CCM);
	if (auths.bit.aes_cmac)
		print_auth_capa(ODP_AUTH_ALG_AES_CMAC);
	if (auths.bit.aes_xcbc_mac)
		print_auth_capa(ODP_AUTH_ALG_AES_XCBC_MAC);
	if (auths.bit.chacha20_poly1305)
		print_auth_capa(ODP_AUTH_ALG_CHACHA20_POLY1305);
}

int main(void)
{
	odp_instance_t inst;
	int i, num_hp, num_hp_print;
	int num_ava, num_work, num_ctrl;
	odp_cpumask_t ava_mask, work_mask, ctrl_mask;
	odp_shm_capability_t shm_capa;
	odp_pool_capability_t pool_capa;
	odp_queue_capability_t queue_capa;
	odp_timer_capability_t timer_capa;
	odp_crypto_capability_t crypto_capa;
	uint64_t huge_page[MAX_HUGE_PAGES];
	char ava_mask_str[ODP_CPUMASK_STR_SIZE];
	char work_mask_str[ODP_CPUMASK_STR_SIZE];
	char ctrl_mask_str[ODP_CPUMASK_STR_SIZE];

	printf("\n");
	printf("ODP system info example\n");
	printf("***********************************************************\n");
	printf("\n");

	if (odp_init_global(&inst, NULL, NULL)) {
		printf("Global init failed.\n");
		return -1;
	}

	if (odp_init_local(inst, ODP_THREAD_CONTROL)) {
		printf("Local init failed.\n");
		return -1;
	}

	odp_sys_info_print();

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
		printf("shm capability failed\n");
		return -1;
	}

	if (odp_pool_capability(&pool_capa)) {
		printf("pool capability failed\n");
		return -1;
	}

	if (odp_queue_capability(&queue_capa)) {
		printf("queue capability failed\n");
		return -1;
	}

	if (odp_timer_capability(ODP_CLOCK_CPU, &timer_capa)) {
		printf("timer capability failed\n");
		return -1;
	}

	if (odp_crypto_capability(&crypto_capa)) {
		printf("crypto capability failed\n");
		return -1;
	}

	printf("\n");
	printf("S Y S T E M    I N F O R M A T I O N\n");
	printf("***********************************************************\n");
	printf("\n");
	printf("  ODP API version:        %s\n", odp_version_api_str());
	printf("  ODP impl name:          %s\n", odp_version_impl_name());
	printf("  ODP impl details:       %s\n", odp_version_impl_str());
	printf("  CPU model:              %s\n", odp_cpu_model_str());
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
	printf("  Page size:              %" PRIu64 " kB\n",
	       odp_sys_page_size() / KB);
	printf("  Default huge page size: %" PRIu64 " kB\n",
	       odp_sys_huge_page_size() / KB);
	printf("  Num huge page sizes:    %i\n", num_hp);

	for (i = 0; i < num_hp_print; i++)
		printf("  Huge page size [%i]:     %" PRIu64 " kB\n",
		       i, huge_page[i] / KB);

	printf("\n");
	printf("  SHM\n");
	printf("    max_blocks:           %u\n", shm_capa.max_blocks);
	printf("    max_size:             %" PRIu64 " MB\n",
	       shm_capa.max_size / MB);
	printf("    max_align:            %" PRIu64 " B\n", shm_capa.max_align);

	printf("\n");
	printf("  POOL\n");
	printf("    max_pools:            %u\n", pool_capa.max_pools);
	printf("    buf.max_pools:        %u\n", pool_capa.buf.max_pools);
	printf("    buf.max_align:        %" PRIu32 " B\n",
	       pool_capa.buf.max_align);
	printf("    buf.max_size:         %" PRIu32 " kB\n",
	       pool_capa.buf.max_size / KB);
	printf("    buf.max_num:          %" PRIu32 "\n",
	       pool_capa.buf.max_num);
	printf("    pkt.max_pools:        %u\n", pool_capa.pkt.max_pools);
	printf("    pkt.max_len:          %" PRIu32 " kB\n",
	       pool_capa.pkt.max_len / KB);
	printf("    pkt.max_num:          %" PRIu32 "\n",
	       pool_capa.pkt.max_num);
	printf("    pkt.max_segs:         %" PRIu32 "\n",
	       pool_capa.pkt.max_segs_per_pkt);
	printf("    pkt.max_seg_len:      %" PRIu32 " B\n",
	       pool_capa.pkt.max_seg_len);
	printf("    pkt.max_uarea:        %" PRIu32 " B\n",
	       pool_capa.pkt.max_uarea_size);
	printf("    tmo.max_pools:        %u\n", pool_capa.tmo.max_pools);
	printf("    tmo.max_num:          %" PRIu32 "\n",
	       pool_capa.tmo.max_num);

	printf("\n");
	printf("  QUEUE\n");
	printf("    max queues:           %" PRIu32 "\n",
	       queue_capa.max_queues);
	printf("    plain.max_num:        %" PRIu32 "\n",
	       queue_capa.plain.max_num);
	printf("    plain.max_size:       %" PRIu32 "\n",
	       queue_capa.plain.max_size);
	printf("    plain.lf.max_num:     %" PRIu32 "\n",
	       queue_capa.plain.lockfree.max_num);
	printf("    plain.lf.max_size:    %" PRIu32 "\n",
	       queue_capa.plain.lockfree.max_size);
	printf("    plain.wf.max_num:     %" PRIu32 "\n",
	       queue_capa.plain.waitfree.max_num);
	printf("    plain.wf.max_size:    %" PRIu32 "\n",
	       queue_capa.plain.waitfree.max_size);

	printf("\n");
	printf("  SCHEDULER\n");
	printf("    max ordered locks:    %" PRIu32 "\n",
	       queue_capa.max_ordered_locks);
	printf("    max groups:           %u\n", queue_capa.max_sched_groups);
	printf("    priorities:           %u\n", queue_capa.sched_prios);
	printf("    sched.max_num:        %" PRIu32 "\n",
	       queue_capa.sched.max_num);
	printf("    sched.max_size:       %" PRIu32 "\n",
	       queue_capa.sched.max_size);
	printf("    sched.lf.max_num:     %" PRIu32 "\n",
	       queue_capa.sched.lockfree.max_num);
	printf("    sched.lf.max_size:    %" PRIu32 "\n",
	       queue_capa.sched.lockfree.max_size);
	printf("    sched.wf.max_num:     %" PRIu32 "\n",
	       queue_capa.sched.waitfree.max_num);
	printf("    sched.wf.max_size:    %" PRIu32 "\n",
	       queue_capa.sched.waitfree.max_size);

	printf("\n");
	printf("  TIMER\n");
	printf("    highest resolution:   %" PRIu64 " nsec\n",
	       timer_capa.highest_res_ns);

	printf("\n");
	printf("  CRYPTO\n");
	printf("    max sessions:         %" PRIu32 "\n",
	       crypto_capa.max_sessions);
	printf("    sync mode support:    %s\n",
	       support_level(crypto_capa.sync_mode));
	printf("    async mode support:   %s\n",
	       support_level(crypto_capa.async_mode));
	printf("    cipher algorithms:    ");
	print_cipher_algos(crypto_capa.ciphers);
	printf("\n");
	print_cipher_caps(crypto_capa.ciphers);
	printf("    auth algorithms:      ");
	print_auth_algos(crypto_capa.auths);
	printf("\n");
	print_auth_caps(crypto_capa.auths);

	printf("\n");
	printf("***********************************************************\n");
	printf("\n");

	if (odp_term_local()) {
		printf("Local term failed.\n");
		return -1;
	}

	if (odp_term_global(inst)) {
		printf("Global term failed.\n");
		return -1;
	}

	return 0;
}
