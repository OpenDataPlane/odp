/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#define RING_SIZE 4096
#define PIECE_BULK 32

#define HALF_BULK (RING_SIZE >> 1)
#define ILLEGAL_SIZE (RING_SIZE | 0x3)

/* test suite start and stop */
int ring_test_basic_start(void);
int ring_test_basic_end(void);

/* basic test cases */
void ring_test_basic_create(void);
void ring_test_basic_burst(void);
void ring_test_basic_bulk(void);
void ring_test_basic_watermark(void);

/* test suite start and stop */
int ring_test_stress_start(void);
int ring_test_stress_end(void);

/* stress test cases */
void ring_test_stress_1_1_producer_consumer(void);
void ring_test_stress_1_N_producer_consumer(void);
void ring_test_stress_N_1_producer_consumer(void);
void ring_test_stress_N_M_producer_consumer(void);
void ring_test_stress_ring_list_dump(void);

int ring_suites_main(int argc, char *argv[]);
