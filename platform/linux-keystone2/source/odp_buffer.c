/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_buffer.h>
#include <odp_buffer_internal.h>
#include <odp_buffer_pool_internal.h>
#include <ti_em_rh.h>

void *odp_buffer_addr(odp_buffer_t buf)
{
	return odp_buf_to_hdr(buf)->buf_vaddr;
}

size_t odp_buffer_size(odp_buffer_t buf)
{
	return (size_t)odp_buf_to_hdr(buf)->desc.origBufferLen;
}

int odp_buffer_type(odp_buffer_t buf)
{
	return odp_buf_to_hdr(buf)->type;
}

int odp_buffer_is_scatter(odp_buffer_t buf)
{
	return (odp_buf_to_hdr(buf)->desc.nextBDPtr) ? 1 : 0;
}


int odp_buffer_is_valid(odp_buffer_t buf)
{
	return (buf != ODP_BUFFER_INVALID);
}


int odp_buffer_snprint(char *str, size_t n, odp_buffer_t buf)
{
	odp_buffer_hdr_t *desc;
	int len = 0;

	if (!odp_buffer_is_valid(buf)) {
		printf("Buffer is not valid.\n");
		return len;
	}

	desc = odp_buf_to_hdr(buf);

	len += snprintf(&str[len], n-len,
			"Buffer\n");
	len += snprintf(&str[len], n-len,
			"  desc_vaddr  %p\n",      desc);
	len += snprintf(&str[len], n-len,
			"  buf_vaddr   %p\n",      desc->buf_vaddr);
	len += snprintf(&str[len], n-len,
			"  buf_paddr_o 0x%x\n",    desc->desc.origBuffPtr);
	len += snprintf(&str[len], n-len,
			"  buf_paddr   0x%x\n",    desc->desc.buffPtr);
	len += snprintf(&str[len], n-len,
			"  pool        %i\n",      odp_buf_to_pool(buf));
	len += snprintf(&str[len], n-len,
			"  free_queue  %u\n",      desc->free_queue);

	len += snprintf(&str[len], n-len, "\n");

	ti_em_rh_dump_mem(desc, sizeof(*desc), "Descriptor dump");
	ti_em_rh_dump_mem(desc->buf_vaddr, 64, "Buffer start");

	return len;
}


void odp_buffer_print(odp_buffer_t buf)
{
	int max_len = 512;
	char str[max_len];
	int len;

	len = odp_buffer_snprint(str, max_len-1, buf);
	str[len] = 0;

	printf("\n%s\n", str);
}

void odp_buffer_copy_scatter(odp_buffer_t buf_dst, odp_buffer_t buf_src)
{
	(void)buf_dst;
	(void)buf_src;
}
