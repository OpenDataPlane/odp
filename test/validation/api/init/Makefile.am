include ../Makefile.inc

# most platforms are expected not to support multiple ODP inits
# following each other: therefore 3 separate binaries are
# created, each containing its ODP init test.
test_PROGRAMS = init_main_abort init_main_log init_main_ok
init_main_abort_SOURCES = init_main_abort.c
init_main_log_SOURCES   = init_main_log.c
init_main_ok_SOURCES    = init_main_ok.c
