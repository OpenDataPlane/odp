FDSERVER_INCLUDES = -I$(top_srcdir)/include

AM_CPPFLAGS = $(FDSERVER_INCLUDES) \
              -W -Wall -Werror -Wstrict-prototypes -Wmissing-prototypes \
              -Wmissing-declarations -Wold-style-definition -Wpointer-arith \
              -Wcast-align -Wnested-externs -Wcast-qual -Wformat-nonliteral \
              -Wformat-security -Wundef -Wwrite-strings -Wformat-truncation=0 \
              -Wformat-overflow=0

check_PROGRAMS = fdserver_api
fdserver_api_SOURCES = fdserver_api.c
fdserver_api_LDADD = $(top_srcdir)/src/.libs/libfdserver.a

TEST_LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) \
                  $(top_srcdir)/build-aux/tap-driver.sh
TESTS = run_tests.sh
EXTRA_DIST = $(TESTS)
