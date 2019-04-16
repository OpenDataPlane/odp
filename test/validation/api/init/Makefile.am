include ../Makefile.inc

# Keep init test cases in separate binaries. Some implementations may not allow
# the same application process to call odp_init_global() multiple times.
test_PROGRAMS = init_defaults init_abort init_log init_num_thr init_feature

init_defaults_CPPFLAGS = -DINIT_TEST=0 $(AM_CPPFLAGS)
init_abort_CPPFLAGS    = -DINIT_TEST=1 $(AM_CPPFLAGS)
init_log_CPPFLAGS      = -DINIT_TEST=2 $(AM_CPPFLAGS)
init_num_thr_CPPFLAGS  = -DINIT_TEST=3 $(AM_CPPFLAGS)
init_feature_CPPFLAGS  = -DINIT_TEST=4 $(AM_CPPFLAGS)

init_defaults_SOURCES = init_main.c
init_abort_SOURCES = init_main.c
init_log_SOURCES = init_main.c
init_num_thr_SOURCES = init_main.c
init_feature_SOURCES = init_main.c
