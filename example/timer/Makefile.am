include $(top_srcdir)/example/Makefile.inc

bin_PROGRAMS = odp_timer_accuracy \
		odp_timer_simple \
		odp_timer_test

odp_timer_accuracy_SOURCES = odp_timer_accuracy.c

odp_timer_simple_SOURCES = odp_timer_simple.c

odp_timer_test_SOURCES = odp_timer_test.c

if test_example
TESTS  = odp_timer_accuracy_run.sh \
	odp_timer_simple
endif

EXTRA_DIST = odp_timer_accuracy_run.sh

.NOTPARALLEL:
