include $(top_srcdir)/example/Makefile.inc

AM_CPPFLAGS = $(OPENSSL_CPPFLAGS)
LDADD += $(OPENSSL_LIBS)

bin_PROGRAMS = odp_ipsec

dist_bin_SCRIPTS = \
		   $(srcdir)/odp_ipsec_run_ah_in.sh \
		   $(srcdir)/odp_ipsec_run_ah_out.sh \
		   $(srcdir)/odp_ipsec_run_ah_tun_in.sh \
		   $(srcdir)/odp_ipsec_run_ah_tun_out.sh \
		   $(srcdir)/odp_ipsec_run_esp_in.sh \
		   $(srcdir)/odp_ipsec_run_esp_out.sh \
		   $(srcdir)/odp_ipsec_run_esp_tun_in.sh \
		   $(srcdir)/odp_ipsec_run_esp_tun_out.sh \
		   $(srcdir)/odp_ipsec_run_live.sh \
		   $(srcdir)/odp_ipsec_run_router.sh \
		   $(srcdir)/odp_ipsec_run_simple.sh

odp_ipsec_SOURCES = odp_ipsec.c \
		    odp_ipsec_sa_db.c \
		    odp_ipsec_sa_db.h \
		    odp_ipsec_sp_db.c \
		    odp_ipsec_sp_db.h \
		    odp_ipsec_fwd_db.c \
		    odp_ipsec_fwd_db.h \
		    odp_ipsec_cache.c \
		    odp_ipsec_cache.h \
		    odp_ipsec_stream.c \
		    odp_ipsec_stream.h \
		    odp_ipsec_misc.h
