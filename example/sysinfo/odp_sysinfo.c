/* Copyright (c) 2018, Linaro Limited
 * Copyright (c) 2022-2023, Nokia
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
	case ODP_CPU_ARCH_ARMV9_0:
		return "ARMv9.0-A";
	case ODP_CPU_ARCH_ARMV9_1:
		return "ARMv9.1-A";
	case ODP_CPU_ARCH_ARMV9_2:
		return "ARMv9.2-A";
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

int main(void)
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
	odp_timer_capability_t timer_capa;
	odp_crypto_capability_t crypto_capa;
	odp_ipsec_capability_t ipsec_capa;
	odp_schedule_capability_t schedule_capa;
	odp_stash_capability_t stash_capa;
	uint64_t huge_page[MAX_HUGE_PAGES];
	char ava_mask_str[ODP_CPUMASK_STR_SIZE];
	char work_mask_str[ODP_CPUMASK_STR_SIZE];
	char ctrl_mask_str[ODP_CPUMASK_STR_SIZE];
	int crypto_ret;
	int ipsec_ret;

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

	printf("\n");
	printf("odp_sys_info_print()\n");
	printf("***********************************************************\n");
	odp_sys_info_print();

	printf("\n");
	printf("odp_sys_config_print()\n");
	printf("***********************************************************\n");
	odp_sys_config_print();

	if (odp_system_info(&sysinfo)) {
		printf("system info call failed\n");
		return -1;
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
		printf("shm capability failed\n");
		return -1;
	}

	if (odp_pool_capability(&pool_capa)) {
		printf("pool capability failed\n");
		return -1;
	}

	if (odp_pool_ext_capability(ODP_POOL_PACKET, &pool_ext_capa)) {
		printf("external packet pool capability failed\n");
		return -1;
	}

	if (odp_cls_capability(&cls_capa)) {
		printf("classifier capability failed\n");
		return -1;
	}

	if (odp_comp_capability(&comp_capa)) {
		printf("compression capability failed\n");
		return -1;
	}

	if (odp_dma_capability(&dma_capa)) {
		printf("dma capability failed\n");
		return -1;
	}

	if (odp_queue_capability(&queue_capa)) {
		printf("queue capability failed\n");
		return -1;
	}

	if (odp_schedule_capability(&schedule_capa)) {
		printf("schedule capability failed\n");
		return -1;
	}

	if (odp_stash_capability(&stash_capa, ODP_STASH_TYPE_DEFAULT)) {
		printf("stash capability failed\n");
		return -1;
	}

	if (odp_timer_capability(ODP_CLOCK_DEFAULT, &timer_capa)) {
		printf("timer capability failed\n");
		return -1;
	}

	crypto_ret = odp_crypto_capability(&crypto_capa);
	if (crypto_ret < 0)
		printf("crypto capability failed\n");

	ipsec_ret = odp_ipsec_capability(&ipsec_capa);
	if (ipsec_ret < 0)
		printf("IPsec capability failed\n");

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

	printf("\n");
	printf("  POOL\n");
	printf("    max_pools:            %u\n", pool_capa.max_pools);
	printf("    buf.max_pools:        %u\n", pool_capa.buf.max_pools);
	printf("    buf.max_align:        %u B\n", pool_capa.buf.max_align);
	printf("    buf.max_size:         %u kB\n", pool_capa.buf.max_size / KB);
	printf("    buf.max_num:          %u\n", pool_capa.buf.max_num);
	printf("    buf.min_cache_size:   %u\n", pool_capa.buf.min_cache_size);
	printf("    buf.max_cache_size:   %u\n", pool_capa.buf.max_cache_size);
	printf("    pkt.max_pools:        %u\n", pool_capa.pkt.max_pools);
	printf("    pkt.max_len:          %u kB\n", pool_capa.pkt.max_len / KB);
	printf("    pkt.max_num:          %u\n", pool_capa.pkt.max_num);
	printf("    pkt.max_align:        %u\n", pool_capa.pkt.max_align);
	printf("    pkt.max_headroom:     %u\n", pool_capa.pkt.max_headroom);
	printf("    pkt.max_segs_per_pkt: %u\n", pool_capa.pkt.max_segs_per_pkt);
	printf("    pkt.max_seg_len:      %u B\n", pool_capa.pkt.max_seg_len);
	printf("    pkt.max_uarea_size:   %u B\n", pool_capa.pkt.max_uarea_size);
	printf("    pkt.max_num_subparam: %u\n", pool_capa.pkt.max_num_subparam);
	printf("    pkt.min_cache_size:   %u\n", pool_capa.pkt.min_cache_size);
	printf("    pkt.max_cache_size:   %u\n", pool_capa.pkt.max_cache_size);
	printf("    tmo.max_pools:        %u\n", pool_capa.tmo.max_pools);
	printf("    tmo.max_num:          %u\n", pool_capa.tmo.max_num);
	printf("    tmo.min_cache_size:   %u\n", pool_capa.tmo.min_cache_size);
	printf("    tmo.max_cache_size:   %u\n", pool_capa.tmo.max_cache_size);
	printf("    vector.max_pools:     %u\n", pool_capa.vector.max_pools);
	printf("    vector.max_num:       %u\n", pool_capa.vector.max_num);
	printf("    vector.max_size:      %u\n", pool_capa.vector.max_size);
	printf("    vector.min_cache_size:%u\n", pool_capa.vector.min_cache_size);
	printf("    vector.max_cache_size:%u\n", pool_capa.vector.max_cache_size);

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

	printf("\n");
	printf("  CLASSIFIER\n");
	printf("    supported_terms:      0x%" PRIx64 "\n", cls_capa.supported_terms.all_bits);
	printf("    max_pmr_terms:        %u\n", cls_capa.max_pmr_terms);
	printf("    available_pmr_terms:  %u\n", cls_capa.available_pmr_terms);
	printf("    max_cos:              %u\n", cls_capa.max_cos);
	printf("    max_hash_queues:      %u\n", cls_capa.max_hash_queues);
	printf("    hash_protocols:       0x%x\n", cls_capa.hash_protocols.all_bits);
	printf("    pmr_range_supported:  %i\n", cls_capa.pmr_range_supported);
	printf("    max_mark:             %" PRIu64 "\n", cls_capa.max_mark);
	printf("    stats.queue:          0x%" PRIx64 "\n", cls_capa.stats.queue.all_counters);

	printf("\n");
	printf("  COMPRESSION\n");
	printf("    max_sessions:         %u\n", comp_capa.max_sessions);
	printf("    compl_algos:          0x%x\n", comp_capa.comp_algos.all_bits);
	printf("    hash_algos:           0x%x\n", comp_capa.hash_algos.all_bits);
	printf("    sync support:         %i\n", comp_capa.sync);
	printf("    async support:        %i\n", comp_capa.async);

	printf("\n");
	printf("  DMA\n");
	printf("    max_sessions:         %u\n", dma_capa.max_sessions);
	printf("    max_transfers:        %u\n", dma_capa.max_transfers);
	printf("    max_src_segs:         %u\n", dma_capa.max_src_segs);
	printf("    max_dst_segs:         %u\n", dma_capa.max_dst_segs);
	printf("    max_segs:             %u\n", dma_capa.max_segs);
	printf("    max_seg_len:          %u\n", dma_capa.max_seg_len);
	printf("    compl_mode_mask:      0x%x\n", dma_capa.compl_mode_mask);
	printf("    queue_type_sched:     %i\n", dma_capa.queue_type_sched);
	printf("    queue_type_plain:     %i\n", dma_capa.queue_type_plain);
	printf("    pool.max_pools:       %u\n", dma_capa.pool.max_pools);
	printf("    pool.max_num:         %u\n", dma_capa.pool.max_num);
	printf("    pool.min_cache_size:  %u\n", dma_capa.pool.min_cache_size);
	printf("    pool.max_cache_size:  %u\n", dma_capa.pool.max_cache_size);

	printf("\n");
	printf("  QUEUE\n");
	printf("    max queues:           %u\n", queue_capa.max_queues);
	printf("    plain.max_num:        %u\n", queue_capa.plain.max_num);
	printf("    plain.max_size:       %u\n", queue_capa.plain.max_size);
	printf("    plain.lf.max_num:     %u\n", queue_capa.plain.lockfree.max_num);
	printf("    plain.lf.max_size:    %u\n", queue_capa.plain.lockfree.max_size);
	printf("    plain.wf.max_num:     %u\n", queue_capa.plain.waitfree.max_num);
	printf("    plain.wf.max_size:    %u\n", queue_capa.plain.waitfree.max_size);

	printf("\n");
	printf("  SCHEDULER\n");
	printf("    max_ordered_locks:    %u\n", schedule_capa.max_ordered_locks);
	printf("    max_groups:           %u\n", schedule_capa.max_groups);
	printf("    max_prios:            %u\n", schedule_capa.max_prios);
	printf("    max_queues:           %u\n", schedule_capa.max_queues);
	printf("    max_queue_size:       %u\n", schedule_capa.max_queue_size);
	printf("    max_flow_id:          %u\n", schedule_capa.max_flow_id);
	printf("    lockfree_queues:      %ssupported\n",
	       schedule_capa.lockfree_queues ? "" : "not ");
	printf("    waitfree_queues:      %ssupported\n",
	       schedule_capa.waitfree_queues ? "" : "not ");

	printf("\n");
	printf("  STASH\n");
	printf("    max_stashes_any_type: %u\n", stash_capa.max_stashes_any_type);
	printf("    max_stashes:          %u\n", stash_capa.max_stashes);
	printf("    max_num_obj:          %" PRIu64 "\n", stash_capa.max_num_obj);
	printf("    max_obj_size:         %u\n", stash_capa.max_obj_size);
	printf("    max_cache_size:       %u\n", stash_capa.max_cache_size);

	printf("\n");
	printf("  TIMER (ODP_CLOCK_DEFAULT)\n");
	printf("    max_pools_combined:   %u\n", timer_capa.max_pools_combined);
	printf("    max_pools:            %u\n", timer_capa.max_pools);
	printf("    max_timers:           %u\n", timer_capa.max_timers);
	printf("    queue_type_sched:     %i\n", timer_capa.queue_type_sched);
	printf("    queue_type_plain:     %i\n", timer_capa.queue_type_plain);
	printf("    highest_res_ns:       %" PRIu64 " nsec\n", timer_capa.highest_res_ns);
	printf("    maximum resolution\n");
	printf("      res_ns:             %" PRIu64 " nsec\n", timer_capa.max_res.res_ns);
	printf("      res_hz:             %" PRIu64 " hz\n", timer_capa.max_res.res_hz);
	printf("      min_tmo:            %" PRIu64 " nsec\n", timer_capa.max_res.min_tmo);
	printf("      max_tmo:            %" PRIu64 " nsec\n", timer_capa.max_res.max_tmo);
	printf("    maximum timeout\n");
	printf("      res_ns:             %" PRIu64 " nsec\n", timer_capa.max_tmo.res_ns);
	printf("      res_hz:             %" PRIu64 " hz\n", timer_capa.max_tmo.res_hz);
	printf("      min_tmo:            %" PRIu64 " nsec\n", timer_capa.max_tmo.min_tmo);
	printf("      max_tmo:            %" PRIu64 " nsec\n", timer_capa.max_tmo.max_tmo);
	printf("\n");

	if (crypto_ret == 0) {
		printf("  CRYPTO\n");
		printf("    max sessions:         %u\n", crypto_capa.max_sessions);
		printf("    sync mode support:    %s\n", support_level(crypto_capa.sync_mode));
		printf("    async mode support:   %s\n", support_level(crypto_capa.async_mode));
		printf("    queue_type_sched:     %i\n", crypto_capa.queue_type_sched);
		printf("    queue_type_plain:     %i\n", crypto_capa.queue_type_plain);
		printf("    cipher algorithms:    ");
		foreach_cipher(crypto_capa.ciphers, print_cipher);
		printf("\n");
		foreach_cipher(crypto_capa.ciphers, print_cipher_capa);
		printf("    auth algorithms:      ");
		foreach_auth(crypto_capa.auths, print_auth);
		printf("\n");
		foreach_auth(crypto_capa.auths, print_auth_capa);
		printf("\n");
	}

	if (ipsec_ret == 0) {
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
		printf("    max anti-replay window size:  %u\n",
		       ipsec_capa.max_antireplay_ws);
		printf("    inline TM pipelining:         %s\n",
		       support_level(ipsec_capa.inline_ipsec_tm));
		printf("    cipher algorithms:            ");
		foreach_cipher(ipsec_capa.ciphers, print_cipher);
		printf("\n");
		printf("    auth algorithms:              ");
		foreach_auth(ipsec_capa.auths, print_auth);
		printf("\n\n");
	}

	printf("  SHM MEMORY BLOCKS:\n");
	odp_shm_print_all();

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
