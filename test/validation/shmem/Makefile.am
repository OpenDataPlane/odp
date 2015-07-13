include ../Makefile.inc

noinst_LIBRARIES = libshmem.a
libshmem_a_SOURCES = shmem.c

bin_PROGRAMS = shmem_main$(EXEEXT)
dist_shmem_main_SOURCES = shmem_main.c
shmem_main_LDADD = libshmem.a $(LIBCUNIT_COMMON) $(LIBODP)
