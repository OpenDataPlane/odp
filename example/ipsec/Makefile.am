include $(top_srcdir)/example/Makefile.inc

bin_PROGRAMS = odp_ipsec
odp_ipsec_LDFLAGS = $(AM_LDFLAGS) -static
odp_ipsec_CFLAGS = $(AM_CFLAGS) -I../

dist_odp_ipsec_SOURCES = odp_ipsec.c \
			 odp_ipsec_sa_db.c \
			 odp_ipsec_sp_db.c \
			 odp_ipsec_fwd_db.c \
			 odp_ipsec_loop_db.c \
			 odp_ipsec_cache.c \
			 odp_ipsec_stream.c
