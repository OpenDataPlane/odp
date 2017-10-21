include ../Makefile.inc

AM_CPPFLAGS += -Wno-error=missing-field-initializers

noinst_LTLIBRARIES = libtestipsec.la
libtestipsec_la_SOURCES = \
	test_vectors.h \
	ipsec_test_in.c \
	ipsec_test_out.c \
	ipsec.h \
	ipsec.c

test_PROGRAMS = \
	ipsec_sync$(EXEEXT) \
	ipsec_async$(EXEEXT) \
	ipsec_inline_in$(EXEEXT) \
	ipsec_inline_out$(EXEEXT)

ipsec_sync_SOURCES = ipsec_sync.c
ipsec_async_SOURCES = ipsec_async.c
ipsec_inline_in_SOURCES = ipsec_inline_in.c
ipsec_inline_out_SOURCES = ipsec_inline_out.c

ipsec_sync_LDADD = libtestipsec.la $(LIBCUNIT_COMMON) $(LIBODP)
ipsec_async_LDADD = libtestipsec.la $(LIBCUNIT_COMMON) $(LIBODP)
ipsec_inline_in_LDADD = libtestipsec.la $(LIBCUNIT_COMMON) $(LIBODP)
ipsec_inline_out_LDADD = libtestipsec.la $(LIBCUNIT_COMMON) $(LIBODP)
