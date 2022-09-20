include $(top_srcdir)/test/Makefile.inc

if test_cpp
bin_PROGRAMS =  odp_api_from_cpp
TESTS = odp_api_from_cpp
endif

odp_api_from_cpp_SOURCES = odp_api_from_cpp.cpp

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
		`$(PKGCONFIG) --static libodphelper` `$(PKGCONFIG) --static lib$(ODP_LIB_NAME)`
if ! cross_compile
	./$@
endif
endif

DISTCLEANFILES = $(PROGRAM_shared) $(PROGRAM_static)
