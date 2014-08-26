/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_buffer.h>
#include <odp_buffer_internal.h>
#include <odp_buffer_pool_internal.h>

#include <string.h>
#include <stdio.h>


void *odp_buffer_addr(odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr = odp_buf_to_hdr(buf);

	return hdr->addr;
}


size_t odp_buffer_size(odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr = odp_buf_to_hdr(buf);

	return hdr->size;
}


int odp_buffer_type(odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr = odp_buf_to_hdr(buf);

	return hdr->type;
}


int odp_buffer_is_valid(odp_buffer_t buf)
{
	odp_buffer_bits_t handle;

	handle.u32 = buf;

	return (handle.index != ODP_BUFFER_INVALID_INDEX);
}


int odp_buffer_snprint(char *str, size_t n, odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr;
	int len = 0;

	if (!odp_buffer_is_valid(buf)) {
		printf("Buffer is not valid.\n");
		return len;
	}

	hdr = odp_buf_to_hdr(buf);

	len += snprintf(&str[len], n-len,
			"Buffer\n");
	len += snprintf(&str[len], n-len,
			"  pool         %i\n",        hdr->pool_hdl);
	len += snprintf(&str[len], n-len,
			"  index        %"PRIu32"\n", hdr->index);
	len += snprintf(&str[len], n-len,
			"  phy_addr     %"PRIu64"\n", hdr->phys_addr);
	len += snprintf(&str[len], n-len,
			"  addr         %p\n",        hdr->addr);
	len += snprintf(&str[len], n-len,
			"  size         %zu\n",       hdr->size);
	len += snprintf(&str[len], n-len,
			"  cur_offset   %zu\n",       hdr->cur_offset);
	len += snprintf(&str[len], n-len,
			"  ref_count    %i\n",        hdr->ref_count);
	len += snprintf(&str[len], n-len,
			"  type         %i\n",        hdr->type);
	len += snprintf(&str[len], n-len,
			"  Scatter list\n");
	len += snprintf(&str[len], n-len,
			"    num_bufs   %i\n",        hdr->scatter.num_bufs);
	len += snprintf(&str[len], n-len,
			"    pos        %i\n",        hdr->scatter.pos);
	len += snprintf(&str[len], n-len,
			"    total_len  %zu\n",       hdr->scatter.total_len);

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
