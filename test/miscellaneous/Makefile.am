include $(top_srcdir)/test/Makefile.inc

bin_PROGRAMS = odp_dyn_workers

if test_cpp
bin_PROGRAMS +=  odp_api_from_cpp
endif

odp_dyn_workers_SOURCES = odp_dyn_workers.c
odp_api_from_cpp_SOURCES = odp_api_from_cpp.cpp

TESTSCRIPTS = odp_dyn_workers_run.sh

TESTS = $(TESTSCRIPTS)

if test_cpp
TESTS += odp_api_from_cpp
endif

noinst_PROGRAMS = odp_api_headers
odp_api_headers_CFLAGS = $(AM_CFLAGS) -Wconversion
odp_api_headers_SOURCES = odp_api_headers.c

PKGCONFIG = PKG_CONFIG_PATH=$(libdir)/pkgconfig:$$PKG_CONFIG_PATH pkg-config --cflags --libs

if enable_shared

PROGRAM_shared = odp_api_headers_shared

installcheck-local: $(PROGRAM_shared)

$(PROGRAM_shared): $(srcdir)/$(odp_api_headers_SOURCES)
	$(CC) $(AM_CFLAGS) $(CFLAGS) $^ -o $@ \
		`$(PKGCONFIG) libodphelper` `$(PKGCONFIG) lib$(ODP_LIB_NAME)`
if ! cross_compile
	LD_LIBRARY_PATH=$(libdir) ./$@
endif
endif

if enable_static

PROGRAM_static = odp_api_headers_static

installcheck-local: $(PROGRAM_static)

$(PROGRAM_static): $(srcdir)/$(odp_api_headers_SOURCES)
	$(CC) $(AM_CFLAGS) $(CFLAGS) $^ -o $@ \
		`$(PKGCONFIG) --static libodphelper | sed "s/-lodphelper/-l:libodphelper.a/"` \
		`$(PKGCONFIG) --static lib$(ODP_LIB_NAME) | sed "s/-l$(ODP_LIB_NAME)/-l:lib$(ODP_LIB_NAME).a/"`
if ! cross_compile
	./$@
endif
endif

DISTCLEANFILES = $(PROGRAM_shared) $(PROGRAM_static)

dist_check_SCRIPTS = $(TESTSCRIPTS)

# If building out-of-tree, make check will not copy the scripts and data to the
# $(builddir) assuming that all commands are run locally. However this prevents
# running tests on a remote target using LOG_COMPILER.
# So copy all script and data files explicitly here.
all-local:
	if [ "x$(srcdir)" != "x$(builddir)" ]; then \
		for f in $(dist_check_SCRIPTS) $(dist_check_DATA); do \
			if [ -e $(srcdir)/$$f ]; then \
				mkdir -p $(builddir)/$$(dirname $$f); \
				cp -f $(srcdir)/$$f $(builddir)/$$f; \
			fi \
		done \
	fi
clean-local:
	if [ "x$(srcdir)" != "x$(builddir)" ]; then \
		for f in $(dist_check_SCRIPTS) $(dist_check_DATA); do \
			rm -f $(builddir)/$$f; \
		done \
	fi
