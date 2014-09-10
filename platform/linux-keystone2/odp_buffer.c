/*
 * Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2014, Texas Instruments Incorporated
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_buffer.h>
#include <odp_buffer_internal.h>
#include <odp_buffer_pool_internal.h>

int odp_buffer_snprint(char *str, size_t n, odp_buffer_t buf)
{
	Cppi_HostDesc *desc;
	int len = 0;

	if (!odp_buffer_is_valid(buf)) {
		printf("Buffer is not valid.\n");
		return len;
	}

	desc = _odp_buf_to_cppi_desc(buf);

	len += snprintf(&str[len], n-len,
			"Buffer\n");
	len += snprintf(&str[len], n-len,
			"  desc_vaddr  %p\n",      desc);
	len += snprintf(&str[len], n-len,
			"  buf_paddr_o 0x%x\n",    desc->origBuffPtr);
	len += snprintf(&str[len], n-len,
			"  buf_paddr   0x%x\n",    desc->buffPtr);
	len += snprintf(&str[len], n-len,
			"  buf_len_o 0x%x\n",      desc->origBufferLen);
	len += snprintf(&str[len], n-len,
			"  buf_len   0x%x\n",      desc->buffLen);
	len += snprintf(&str[len], n-len,
			"  pool        %p\n",      odp_buf_to_pool(buf));

	len += snprintf(&str[len], n-len, "\n");

	return len;
}

void odp_buffer_print(odp_buffer_t buf)
{
	int max_len = 512;
	char str[max_len];
	int len;
	Cppi_HostDesc *desc;

	len = odp_buffer_snprint(str, max_len-1, buf);
	if (!len)
		return;
	str[len] = 0;

	printf("\n%s\n", str);

	desc = _odp_buf_to_cppi_desc(buf);
	odp_print_mem(desc, sizeof(*desc), "Descriptor dump");
	odp_print_mem((void *)desc->origBuffPtr,
		      desc->buffPtr - desc->origBuffPtr + 128,
		      "Buffer start");
}

void odp_buffer_copy_scatter(odp_buffer_t buf_dst, odp_buffer_t buf_src)
{
	(void)buf_dst;
	(void)buf_src;
}
