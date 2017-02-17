include $(top_srcdir)/platform/@with_platform@/Makefile.inc

LIB   = $(top_builddir)/lib

#in the following line, the libs using the symbols should come before
#the libs containing them! The includer is given a chance to add things
#before libodp by setting PRE_LDADD before the inclusion.
LDADD = $(PRE_LDADD) $(LIB)/libodphelper.la $(LIB)/libodp-linux.la

INCFLAGS = \
	-I$(top_builddir)/platform/@with_platform@/include \
	-I$(top_srcdir)/helper/include \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/include/odp/arch/@ARCH_ABI@ \
	-I$(top_srcdir)/platform/@with_platform@/include \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/helper

ODP_PLATFORM=${with_platform}

AM_CFLAGS += $(INCFLAGS)
AM_LDFLAGS += -static

EXECUTABLES = chksum$(EXEEXT) \
              cuckootable$(EXEEXT) \
              parse$(EXEEXT)\
              table$(EXEEXT) \
              iplookuptable$(EXEEXT)

#These are platform specific extensions that are not portable
#They are a convenience to app writers who have chosen to
#restrict their application to Linux.

if helper_linux
EXECUTABLES += linux/pthread$(EXEEXT) \
	       linux/process$(EXEEXT)
endif

COMPILE_ONLY = odpthreads

TESTSCRIPTS = odpthreads_as_processes \
	      odpthreads_as_pthreads

if test_helper
TESTS = $(EXECUTABLES) $(TESTSCRIPTS)
endif

dist_bin_SCRIPTS =

test_PROGRAMS = $(EXECUTABLES) $(COMPILE_ONLY)

EXTRA_DIST = odpthreads_as_processes odpthreads_as_pthreads

dist_chksum_SOURCES = chksum.c
dist_cuckootable_SOURCES = cuckootable.c
dist_odpthreads_SOURCES = odpthreads.c
dist_parse_SOURCES = parse.c
dist_table_SOURCES = table.c
dist_iplookuptable_SOURCES = iplookuptable.c
