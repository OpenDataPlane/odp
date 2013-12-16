/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 *    * Neither the name of Linaro Limited nor the names of its contributors
 *      may be used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIALDAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */


#include <odp_packet_io.h>
#include <odp_internal.h>
#include <odp_spinlock.h>
#include <odp_shared_memory.h>
#include <odp_packet_socket.h>

#include <string.h>
#include <stdio.h>

#define ODP_CONFIG_PKTIO_ENTRIES 512

typedef struct {
	pkt_sock_t pkt_sock;	/**< using socket API for IO */
	int taken;		/**< is entry taken(1) or free(0) */
} pktio_entry_t;

typedef struct {
	odp_spinlock_t tbl_lock;
	pktio_entry_t entries[ODP_CONFIG_PKTIO_ENTRIES] ODP_ALIGNED_CACHE;
} pktio_table_t;


static pktio_table_t *pktio_tbl;


int odp_pktio_init_global(void)
{
	pktio_tbl = odp_shm_reserve("odp_pktio_entries",
				    sizeof(pktio_table_t),
				    sizeof(pktio_entry_t));
	if (pktio_tbl == NULL)
		return -1;

	memset(pktio_tbl, 0, sizeof(pktio_table_t));

	odp_spinlock_init(&pktio_tbl->tbl_lock);

	return 0;
}

int odp_pktio_init_local(void)
{
	return 0;
}

static int is_free(pktio_entry_t *entry)
{
	return (entry->taken == 0);
}

static void set_free(pktio_entry_t *entry)
{
	entry->taken = 0;
}

static void set_taken(pktio_entry_t *entry)
{
	entry->taken = 1;
}

static void init_pktio_entry(pktio_entry_t *entry)
{
	memset(&entry->pkt_sock, 0, sizeof(entry->pkt_sock));
	set_taken(entry);
}

static odp_pktio_t alloc_pktio_entry(void)
{
	odp_pktio_t id = ODP_PKTIO_INVALID;
	int i;

	odp_spinlock_lock(&pktio_tbl->tbl_lock);

	for (i = 0; i < ODP_CONFIG_PKTIO_ENTRIES; ++i) {
		if (is_free(&pktio_tbl->entries[i])) {
			init_pktio_entry(&pktio_tbl->entries[i]);
			id = i + 1;
			break;
		}
	}

	odp_spinlock_unlock(&pktio_tbl->tbl_lock);

	return id;
}

static int free_pktio_entry(odp_pktio_t id)
{
	int i;

	if (id == ODP_PKTIO_INVALID || id > ODP_CONFIG_PKTIO_ENTRIES)
		return -1;

	i = id - 1;

	odp_spinlock_lock(&pktio_tbl->tbl_lock);

	set_free(&pktio_tbl->entries[i]);

	odp_spinlock_unlock(&pktio_tbl->tbl_lock);

	return 0;
}

static pktio_entry_t *get_entry(odp_pktio_t id)
{
	if (id == ODP_PKTIO_INVALID || id > ODP_CONFIG_PKTIO_ENTRIES)
		return NULL;

	return &pktio_tbl->entries[id - 1];
}

odp_pktio_t odp_pktio_open(char *dev, odp_buffer_pool_t pool)
{
	odp_pktio_t id;
	pktio_entry_t *pktio_entry;
	int res;

	id = alloc_pktio_entry();
	if (id == ODP_PKTIO_INVALID) {
		fprintf(stderr, "%s(): No resources available.\n", __func__);
		return ODP_PKTIO_INVALID;
	}

	pktio_entry = get_entry(id);
	if (pktio_entry == NULL)
		return ODP_PKTIO_INVALID;

	res = setup_pkt_sock(&pktio_entry->pkt_sock, dev, pool);
	if (res == -1)
		return ODP_PKTIO_INVALID;

	return id;
}

int odp_pktio_close(odp_pktio_t id)
{
	pktio_entry_t *pktio_entry;
	int res;

	pktio_entry = get_entry(id);
	if (pktio_entry == NULL)
		return -1;

	res  = close_pkt_sock(&pktio_entry->pkt_sock);
	res |= free_pktio_entry(id);
	if (res != 0)
		return -1;

	return 0;
}

int odp_pktio_recv(odp_pktio_t id, odp_packet_t pkt_table[], unsigned len)
{
	pktio_entry_t *pktio_entry = get_entry(id);

	return recv_pkt_sock(&pktio_entry->pkt_sock, pkt_table, len);
}

int odp_pktio_send(odp_pktio_t id, odp_packet_t pkt_table[], unsigned len)
{
	pktio_entry_t *pktio_entry = get_entry(id);

	return send_pkt_sock(&pktio_entry->pkt_sock, pkt_table, len);
}

