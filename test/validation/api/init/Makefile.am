include ../Makefile.inc

# most platforms are expected not to support multiple ODP inits
# following each other: therefore 3 separate binaries are
# created, each containing its ODP init test.
test_PROGRAMS = init_main_abort init_main_log init_main_ok
init_main_abort_SOURCES = init_main_abort.c init.c init.h
init_main_log_SOURCES   = init_main_log.c init.c init.h
init_main_ok_SOURCES    = init_main_ok.c init.c init.h
init_main_abort_LDADD = $(LIBCUNIT_COMMON) $(LIBODP)
init_main_log_LDADD   = $(LIBCUNIT_COMMON) $(LIBODP)
init_main_ok_LDADD    = $(LIBCUNIT_COMMON) $(LIBODP)
