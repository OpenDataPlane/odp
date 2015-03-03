/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/buffer.h>
#include <odp_buffer_internal.h>
#include <odp_pool_internal.h>

#include <string.h>
#include <stdio.h>


void *odp_buffer_addr(odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr = odp_buf_to_hdr(buf);

	return hdr->mb.buf_addr;
}


size_t odp_buffer_size(odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr = odp_buf_to_hdr(buf);
	struct rte_mbuf *mbuf = (struct rte_mbuf *)hdr;

	return mbuf->buf_len;

}


int odp_buffer_type(odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr = odp_buf_to_hdr(buf);
	struct rte_mbuf *mbuf = (struct rte_mbuf *)hdr;

	return mbuf->type;

}


int odp_buffer_is_valid(odp_buffer_t buf)
{
	/* We could call rte_mbuf_sanity_check, but that panics
	 * and aborts the program */
	return (void *)buf != NULL;
}


int odp_buffer_snprint(char *str, uint32_t n, odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr;
	int len = 0;

	if (!odp_buffer_is_valid(buf)) {
		ODP_PRINT("Buffer is not valid.\n");
		return len;
	}

	hdr = odp_buf_to_hdr(buf);

	len += snprintf(&str[len], n-len,
			"Buffer\n");
	len += snprintf(&str[len], n-len,
			"  pool         %"PRIu64"\n", (int64_t) hdr->mb.pool);
	len += snprintf(&str[len], n-len,
			"  phy_addr     %"PRIu64"\n", hdr->mb.buf_physaddr);
	len += snprintf(&str[len], n-len,
			"  addr         %p\n",        hdr->mb.buf_addr);
	len += snprintf(&str[len], n-len,
			"  size         %u\n",        hdr->mb.buf_len);
	len += snprintf(&str[len], n-len,
			"  ref_count    %i\n",
			odp_atomic_load_u32((odp_atomic_u32_t *)
					    &hdr->mb.refcnt));

	len += snprintf(&str[len], n-len,
			"  dpdk type    %i\n",        hdr->mb.type);
	len += snprintf(&str[len], n-len,
			"  odp type     %i\n",        hdr->type);

	return len;
}


void odp_buffer_print(odp_buffer_t buf)
{
	int max_len = 512;
	char str[max_len];
	int len;

	len = odp_buffer_snprint(str, max_len-1, buf);
	str[len] = 0;

	ODP_PRINT("\n%s\n", str);
}
