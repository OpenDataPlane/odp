include $(top_srcdir)/example/Makefile.inc

bin_PROGRAMS = odp_ipsec_offload$(EXEEXT)
odp_ipsec_offload_LDFLAGS = $(AM_LDFLAGS) -static
odp_ipsec_offload_CFLAGS = $(AM_CFLAGS) -I${top_srcdir}/example

noinst_HEADERS = \
		  $(top_srcdir)/example/ipsec_offload/odp_ipsec_offload_cache.h \
		  $(top_srcdir)/example/ipsec_offload/odp_ipsec_offload_fwd_db.h \
		  $(top_srcdir)/example/ipsec_offload/odp_ipsec_offload_misc.h \
		  $(top_srcdir)/example/ipsec_offload/odp_ipsec_offload_sa_db.h \
		  $(top_srcdir)/example/ipsec_offload/odp_ipsec_offload_sp_db.h \
		  $(top_srcdir)/example/example_debug.h

dist_odp_ipsec_offload_SOURCES = odp_ipsec_offload.c \
			 odp_ipsec_offload_sa_db.c \
			 odp_ipsec_offload_sp_db.c \
			 odp_ipsec_offload_fwd_db.c \
			 odp_ipsec_offload_cache.c
