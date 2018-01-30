include $(top_srcdir)/example/Makefile.inc

bin_PROGRAMS = odp_ipfragreass$(EXEEXT)
odp_ipfragreass_LDFLAGS = $(AM_LDFLAGS) -static
odp_ipfragreass_CFLAGS = $(AM_CFLAGS) -I${top_srcdir}/example

noinst_HEADERS = \
		  $(top_srcdir)/example/ipfragreass/odp_ipfragreass_atomics.h \
		  $(top_srcdir)/example/ipfragreass/odp_ipfragreass_atomics_arm.h \
		  $(top_srcdir)/example/ipfragreass/odp_ipfragreass_fragment.h \
		  $(top_srcdir)/example/ipfragreass/odp_ipfragreass_helpers.h \
		  $(top_srcdir)/example/ipfragreass/odp_ipfragreass_ip.h \
		  $(top_srcdir)/example/ipfragreass/odp_ipfragreass_reassemble.h \
		  $(top_srcdir)/example/example_debug.h

dist_odp_ipfragreass_SOURCES = odp_ipfragreass.c \
			       odp_ipfragreass_fragment.c \
			       odp_ipfragreass_helpers.c \
			       odp_ipfragreass_reassemble.c

if test_example
TESTS = odp_ipfragreass
endif
