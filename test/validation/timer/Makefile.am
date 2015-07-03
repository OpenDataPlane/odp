include ../Makefile.inc

noinst_LIBRARIES = libtimer.a
libtimer_a_SOURCES = timer.c

bin_PROGRAMS = timer_main$(EXEEXT)
dist_timer_main_SOURCES = timer_main.c
timer_main_LDADD = libtimer.a $(LIBCUNIT_COMMON) $(LIBODP)
