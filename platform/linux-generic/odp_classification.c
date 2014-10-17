#include <odp_classification.h>
#include <odp_align.h>
#include <odp_queue.h>
#include <odp_debug.h>
#include <odp_debug_internal.h>
#include <odp_packet_io.h>

odp_cos_t odp_cos_create(const char *name)
{
	(void) name;
	ODP_UNIMPLEMENTED();
	return 0;
}

int odp_cos_destroy(odp_cos_t cos_id)
{
	(void)cos_id;
	ODP_UNIMPLEMENTED();
	return 0;
}

int odp_cos_set_queue(odp_cos_t cos_id, odp_queue_t queue_id)
{
	(void)cos_id;
	(void)queue_id;
	ODP_UNIMPLEMENTED();
	return 0;
}

int odp_cos_set_queue_group(odp_cos_t cos_id, odp_queue_group_t queue_group_id)
{
	(void)cos_id;
	(void)queue_group_id;
	ODP_UNIMPLEMENTED();
	return 0;
}

int odp_cos_set_pool(odp_cos_t cos_id, odp_buffer_pool_t pool_id)
{
	(void)cos_id;
	(void) pool_id;
	ODP_UNIMPLEMENTED();
	return 0;
}


int odp_cos_set_drop(odp_cos_t cos_id, odp_drop_e drop_policy)
{
	(void)cos_id;
	(void)drop_policy;
	ODP_UNIMPLEMENTED();
	return 0;
}

int odp_pktio_set_default_cos(odp_pktio_t pktio_in, odp_cos_t default_cos)
{
	(void)pktio_in;
	(void)default_cos;
	ODP_UNIMPLEMENTED();
	return 0;
}
int odp_pktio_set_error_cos(odp_pktio_t pktio_in, odp_cos_t error_cos)
{
	(void)pktio_in;
	(void)error_cos;
	ODP_UNIMPLEMENTED();
	return 0;
}

int odp_pktio_set_skip(odp_pktio_t pktio_in, size_t offset)
{
	(void)pktio_in;
	(void)offset;
	ODP_UNIMPLEMENTED();
	return 0;
}

int odp_pktio_set_headroom(odp_pktio_t port_id, size_t headroom)
{
	(void)port_id;
	(void)headroom;
	ODP_UNIMPLEMENTED();
	return 0;
}
int odp_cos_set_headroom(odp_cos_t cos_id, size_t req_room)
{
	(void)cos_id;
	(void)req_room;
	ODP_UNIMPLEMENTED();
	return 0;
}

int odp_cos_with_l2_priority(odp_pktio_t pktio_in,
			     size_t num_qos,
			     uint8_t qos_table[],
			     odp_cos_t cos_table[])
{
	(void)pktio_in;
	(void)num_qos;
	(void)qos_table;
	(void)cos_table;
	ODP_UNIMPLEMENTED();
	return 0;
}

int odp_cos_with_l3_qos(odp_pktio_t pktio_in,
			size_t num_qos,
			uint8_t qos_table[],
			odp_cos_t cos_table[],
			bool l3_preference)
{
	(void)pktio_in;
	(void)num_qos;
	(void)qos_table;
	(void)cos_table;
	(void)l3_preference;
	ODP_UNIMPLEMENTED();
	return 0;
}

odp_cos_flow_set_t
odp_cos_class_flow_signature(odp_cos_t cos_id,
			     odp_cos_flow_set_t req_data_set)
{
	(void)cos_id;
	(void)req_data_set;
	ODP_UNIMPLEMENTED();
	return 0;
}
odp_cos_flow_set_t
odp_cos_port_flow_signature(odp_pktio_t pktio_in,
			    odp_cos_flow_set_t req_data_set)
{
	(void)pktio_in;
	(void)req_data_set;
	ODP_UNIMPLEMENTED();
	return 0;
}

odp_pmr_t odp_pmr_create_match(odp_pmr_term_e term,
			       const void *val,
			       const void *mask,
			       size_t val_sz)
{
	(void)term;
	(void)val;
	(void)mask;
	(void)val_sz;
	ODP_UNIMPLEMENTED();
	return 0;
}

odp_pmr_t odp_pmr_create_range(odp_pmr_term_e term,
			       const void *val1,
			       const void *val2,
			       size_t val_sz)
{
	(void)term;
	(void)val1;
	(void)val2;
	(void)val_sz;
	ODP_UNIMPLEMENTED();
	return 0;
}
int odp_pmr_destroy(odp_pmr_t pmr_id)
{
	(void)pmr_id;
	ODP_UNIMPLEMENTED();
	return 0;
}

int odp_pktio_pmr_cos(odp_pmr_t pmr_id,
		      odp_pktio_t src_pktio,
		      odp_cos_t dst_cos)
{
	(void)pmr_id;
	(void)src_pktio;
	(void)dst_cos;
	ODP_UNIMPLEMENTED();
	return 0;
}

int odp_cos_pmr_cos(odp_pmr_t pmr_id, odp_cos_t src_cos, odp_cos_t dst_cos)
{
	(void)pmr_id;
	(void)src_cos;
	(void)dst_cos;
	ODP_UNIMPLEMENTED();
	return 0;
}

signed long odp_pmr_match_count(odp_pmr_t pmr_id)
{
	(void)pmr_id;
	ODP_UNIMPLEMENTED();
	return 0;
}

unsigned long long odp_pmr_terms_cap(void)
{
	ODP_UNIMPLEMENTED();
	return 0;
}

unsigned odp_pmr_terms_avail(void)
{
	ODP_UNIMPLEMENTED();
	return 0;
}

int odp_pmr_match_set_create(int num_terms, odp_pmr_match_t *terms,
			     odp_pmr_set_t *pmr_set_id)
{
	(void)num_terms;
	(void)terms;
	(void)pmr_set_id;
	ODP_UNIMPLEMENTED();
	return 0;
}

int odp_pmr_match_set_destroy(odp_pmr_set_t pmr_set_id)
{
	(void)pmr_set_id;
	ODP_UNIMPLEMENTED();
	return 0;
}

int odp_pktio_pmr_match_set_cos(odp_pmr_set_t pmr_set_id, odp_pktio_t src_pktio,
				odp_cos_t dst_cos)
{
	(void)pmr_set_id;
	(void)src_pktio;
	(void)dst_cos;
	ODP_UNIMPLEMENTED();
	return 0;
}
