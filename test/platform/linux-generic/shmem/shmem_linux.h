/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

void test_success(char *fifo_name, int fd, pid_t odp_app);
void test_failure(char *fifo_name, int fd, pid_t odp_app);
int main(int argc, char *argv[]);
