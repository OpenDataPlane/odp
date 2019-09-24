/* Copyright (c) 2016-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include <stdio.h>
#include <string.h>

static int different_mac(odph_ethaddr_t *mac1, odph_ethaddr_t *mac2)
{
	return mac1->addr[0] != mac2->addr[0] ||
	       mac1->addr[1] != mac2->addr[1] ||
	       mac1->addr[2] != mac2->addr[2] ||
	       mac1->addr[3] != mac2->addr[3] ||
	       mac1->addr[4] != mac2->addr[4] ||
	       mac1->addr[5] != mac2->addr[5];
}

static int different_ipv4(uint32_t *ip_addr1, uint32_t *ip_addr2)
{
	return *ip_addr1 != *ip_addr2;
}

static int test_mac(void)
{
	odph_ethaddr_t mac;
	odph_ethaddr_t ref;

	memset(&ref, 0, sizeof(odph_ethaddr_t));
	memset(&mac, 0, sizeof(odph_ethaddr_t));

	/*
	 * Erroneous strings
	 */

	/* String must not start with other chars */
	if (!odph_eth_addr_parse(&mac, "foo 01:02:03:04:05:06")) {
		ODPH_ERR("Accepted bad string\n");
		return -1;
	}

	/* Missing digit */
	if (!odph_eth_addr_parse(&mac, "01:02:03:04:05:")) {
		ODPH_ERR("Accepted bad string\n");
		return -1;
	}

	/* Missing colon */
	if (!odph_eth_addr_parse(&mac, "01:02:03:04:05 06")) {
		ODPH_ERR("Accepted bad string\n");
		return -1;
	}

	/* Too large value */
	if (!odph_eth_addr_parse(&mac, "01:02:03:04:05:1ff")) {
		ODPH_ERR("Accepted bad string\n");
		return -1;
	}

	/* Negative value */
	if (!odph_eth_addr_parse(&mac, "-1:02:03:04:05:06")) {
		ODPH_ERR("Accepted bad string\n");
		return -1;
	}

	/* Failed function call must not store address */
	if (different_mac(&mac, &ref)) {
		ODPH_ERR("Modified address when failed\n");
		return -1;
	}

	ref.addr[0] = 1;
	ref.addr[1] = 2;
	ref.addr[2] = 3;
	ref.addr[3] = 4;
	ref.addr[4] = 5;
	ref.addr[5] = 6;

	/* Zero pre-fixed */
	memset(&mac, 0, sizeof(odph_ethaddr_t));
	if (odph_eth_addr_parse(&mac, "01:02:03:04:05:06")) {
		ODPH_ERR("Parse call failed\n");
		return -1;
	}

	if (different_mac(&mac, &ref)) {
		ODPH_ERR("Bad parse result\n");
		return -1;
	}

	/* Not zero pre-fixed */
	memset(&mac, 0, sizeof(odph_ethaddr_t));
	if (odph_eth_addr_parse(&mac, "1:2:3:4:5:6")) {
		ODPH_ERR("Parse call failed\n");
		return -1;
	}

	if (different_mac(&mac, &ref)) {
		ODPH_ERR("Bad parse result\n");
		return -1;
	}

	/* String may continue with other chars */
	memset(&mac, 0, sizeof(odph_ethaddr_t));
	if (odph_eth_addr_parse(&mac, "01:02:03:04:05:06 foobar")) {
		ODPH_ERR("Parse call failed\n");
		return -1;
	}

	if (different_mac(&mac, &ref)) {
		ODPH_ERR("Bad parse result\n");
		return -1;
	}

	ref.addr[0] = 0xa;
	ref.addr[1] = 0xb;
	ref.addr[2] = 0xc;
	ref.addr[3] = 0xd;
	ref.addr[4] = 0xe;
	ref.addr[5] = 0xf;

	/* Zero pre-fixed */
	memset(&mac, 0, sizeof(odph_ethaddr_t));
	if (odph_eth_addr_parse(&mac, "0a:0b:0c:0d:0e:0f")) {
		ODPH_ERR("Parse call failed\n");
		return -1;
	}

	if (different_mac(&mac, &ref)) {
		ODPH_ERR("Bad parse result\n");
		return -1;
	}

	/* Not zero pre-fixed */
	memset(&mac, 0, sizeof(odph_ethaddr_t));
	if (odph_eth_addr_parse(&mac, "a:b:c:d:e:f")) {
		ODPH_ERR("Parse call failed\n");
		return -1;
	}

	if (different_mac(&mac, &ref)) {
		ODPH_ERR("Bad parse result\n");
		return -1;
	}

	ref.addr[0] = 0x1a;
	ref.addr[1] = 0x2b;
	ref.addr[2] = 0x3c;
	ref.addr[3] = 0x4d;
	ref.addr[4] = 0x5e;
	ref.addr[5] = 0x6f;

	/* Dual digits */
	memset(&mac, 0, sizeof(odph_ethaddr_t));
	if (odph_eth_addr_parse(&mac, "1a:2b:3c:4d:5e:6f")) {
		ODPH_ERR("Parse call failed\n");
		return -1;
	}

	if (different_mac(&mac, &ref)) {
		ODPH_ERR("Bad parse result\n");
		return -1;
	}

	memset(&ref, 0, sizeof(odph_ethaddr_t));

	/* All zeros */
	memset(&mac, 0, sizeof(odph_ethaddr_t));
	if (odph_eth_addr_parse(&mac, "00:00:00:00:00:00")) {
		ODPH_ERR("Parse call failed\n");
		return -1;
	}

	if (different_mac(&mac, &ref)) {
		ODPH_ERR("Bad parse result\n");
		return -1;
	}

	memset(&ref, 0xff, sizeof(odph_ethaddr_t));

	/* All ones */
	memset(&mac, 0, sizeof(odph_ethaddr_t));
	if (odph_eth_addr_parse(&mac, "ff:ff:ff:ff:ff:ff")) {
		ODPH_ERR("Parse call failed\n");
		return -1;
	}

	if (different_mac(&mac, &ref)) {
		ODPH_ERR("Bad parse result\n");
		return -1;
	}

	printf("MAC address parse test successful\n");
	return 0;
}

static int test_ipv4(void)
{
	uint32_t ip_addr;
	uint32_t ref;

	ip_addr = 0;
	ref     = 0;

	/*
	 * Erroneous strings
	 */

	/* String must not start with other chars */
	if (!odph_ipv4_addr_parse(&ip_addr, "foo 1.2.3.4")) {
		ODPH_ERR("Accepted bad string\n");
		return -1;
	}

	/* Missing digit */
	if (!odph_ipv4_addr_parse(&ip_addr, "1.2.3.")) {
		ODPH_ERR("Accepted bad string\n");
		return -1;
	}

	/* Missing dot */
	if (!odph_ipv4_addr_parse(&ip_addr, "1.2.3 4")) {
		ODPH_ERR("Accepted bad string\n");
		return -1;
	}

	/* Too large value */
	if (!odph_ipv4_addr_parse(&ip_addr, "1.2.3.256")) {
		ODPH_ERR("Accepted bad string\n");
		return -1;
	}

	/* Negative value */
	if (!odph_ipv4_addr_parse(&ip_addr, "-1.2.3.4")) {
		ODPH_ERR("Accepted bad string\n");
		return -1;
	}

	/* Failed function call must not store address */
	if (different_ipv4(&ip_addr, &ref)) {
		ODPH_ERR("Modified address when failed\n");
		return -1;
	}

	ref = 0x01020304;

	/* Zero pre-fixed */
	ip_addr = 0;
	if (odph_ipv4_addr_parse(&ip_addr, "001.002.003.004")) {
		ODPH_ERR("Parse call failed\n");
		return -1;
	}

	if (different_ipv4(&ip_addr, &ref)) {
		ODPH_ERR("Bad parse result\n");
		return -1;
	}

	/* Not zero pre-fixed */
	ip_addr = 0;
	if (odph_ipv4_addr_parse(&ip_addr, "1.2.3.4")) {
		ODPH_ERR("Parse call failed\n");
		return -1;
	}

	if (different_ipv4(&ip_addr, &ref)) {
		ODPH_ERR("Bad parse result\n");
		return -1;
	}

	/* String may continue with other chars */
	ip_addr = 0;
	if (odph_ipv4_addr_parse(&ip_addr, "1.2.3.4 foobar")) {
		ODPH_ERR("Parse call failed\n");
		return -1;
	}

	if (different_ipv4(&ip_addr, &ref)) {
		ODPH_ERR("Bad parse result\n");
		return -1;
	}

	ref = 0x1a2b3c4d;

	/* Dual digits */
	ip_addr = 0;
	if (odph_ipv4_addr_parse(&ip_addr, "26.43.60.77")) {
		ODPH_ERR("Parse call failed\n");
		return -1;
	}

	if (different_ipv4(&ip_addr, &ref)) {
		ODPH_ERR("Bad parse result\n");
		return -1;
	}

	ref = 0xa1b2c3d4;

	/* Triple digits */
	ip_addr = 0;
	if (odph_ipv4_addr_parse(&ip_addr, "161.178.195.212")) {
		ODPH_ERR("Parse call failed\n");
		return -1;
	}

	if (different_ipv4(&ip_addr, &ref)) {
		ODPH_ERR("Bad parse result\n");
		return -1;
	}

	ref = 0;

	/* All zeros */
	ip_addr = 0;
	if (odph_ipv4_addr_parse(&ip_addr, "0.0.0.0")) {
		ODPH_ERR("Parse call failed\n");
		return -1;
	}

	if (different_ipv4(&ip_addr, &ref)) {
		ODPH_ERR("Bad parse result\n");
		return -1;
	}

	ref = 0xffffffff;

	/* All ones */
	ip_addr = 0;
	if (odph_ipv4_addr_parse(&ip_addr, "255.255.255.255")) {
		ODPH_ERR("Parse call failed\n");
		return -1;
	}

	if (different_ipv4(&ip_addr, &ref)) {
		ODPH_ERR("Bad parse result\n");
		return -1;
	}

	printf("IPv4 address parse test successful\n");
	return 0;
}

int main(void)
{
	int ret = 0;

	ret += test_mac();
	ret += test_ipv4();

	return ret;
}
