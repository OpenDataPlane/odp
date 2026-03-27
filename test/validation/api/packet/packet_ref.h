/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Nokia
 */

#ifndef _ODP_TEST_PACKET_REF_H_
#define _ODP_TEST_PACKET_REF_H_

#include <odp_api.h>

int packet_ref_suite_init(void);
int packet_ref_suite_term(void);

void packet_check_default_meta(odp_packet_t pkt); /* from packet.c */

#endif
