include ../Makefile.inc

noinst_LIBRARIES = librandom.a
librandom_a_SOURCES = random.c

bin_PROGRAMS = random_main$(EXEEXT)
dist_random_main_SOURCES = random_main.c
random_main_LDADD = librandom.a $(LIBCUNIT_COMMON) $(LIBODP)
