include $(top_srcdir)/example/Makefile.inc

bin_PROGRAMS = odp_simple_pipeline

odp_simple_pipeline_SOURCES = odp_simple_pipeline.c

if test_example
if HAVE_PCAP
TESTS = simple_pipeline_run.sh
endif
endif
EXTRA_DIST = simple_pipeline_run.sh udp64.pcap
