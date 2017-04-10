include $(top_srcdir)/example/Makefile.inc

bin_PROGRAMS = odp_ipsec_offload

odp_ipsec_offload_SOURCES = odp_ipsec_offload.c \
			    odp_ipsec_offload_misc.h \
			    odp_ipsec_offload_sa_db.c \
			    odp_ipsec_offload_sp_db.c \
			    odp_ipsec_offload_fwd_db.c \
			    odp_ipsec_offload_fwd_db.h \
			    odp_ipsec_offload_cache.c \
			    odp_ipsec_offload_cache.h \
			    odp_ipsec_offload_sa_db.h \
			    odp_ipsec_offload_sp_db.h

dist_noinst_SCRIPTS = \
		      run_left.sh \
		      run_right.sh
