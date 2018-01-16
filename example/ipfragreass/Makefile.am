include $(top_srcdir)/example/Makefile.inc

LDADD += $(ATOMIC_LIBS)

bin_PROGRAMS = odp_ipfragreass

odp_ipfragreass_SOURCES = odp_ipfragreass.c \
			  odp_ipfragreass_fragment.c \
			  odp_ipfragreass_helpers.c \
			  odp_ipfragreass_reassemble.c \
			  odp_ipfragreass_atomics.h \
			  odp_ipfragreass_atomics_arm.h \
			  odp_ipfragreass_fragment.h \
			  odp_ipfragreass_helpers.h \
			  odp_ipfragreass_ip.h \
			  odp_ipfragreass_reassemble.h

if test_example
TESTS = odp_ipfragreass
endif
