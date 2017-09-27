include ../Makefile.inc

test_PROGRAMS = comp_main$(EXEEXT) odp_comp_test_file$(EXEEXT)

comp_main_SOURCES = comp_main.c \
		      comp.c \
		      comp.h \
		      odp_comp_test.c \
		      odp_comp_test.h \
		      comp_ofs_test.c \
		      test_vectors.h

odp_comp_test_file_SOURCES = odp_comp_test_file.c

comp_main_LDADD = $(LIBCUNIT_COMMON) $(LIBODP)
odp_comp_test_file_LDADD = $(LIBCNIT_COMMON) $(LIBODP)
