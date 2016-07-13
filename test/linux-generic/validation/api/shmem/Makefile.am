include ../Makefile.inc

#the main test program is shmem_linux, which, in turn, starts a shmem_odp:
test_PROGRAMS = shmem_linux$(EXEEXT)
test_extra_PROGRAMS = shmem_odp$(EXEEXT)
test_extradir = $(testdir)

#shmem_linux is stand alone, pure linux (no ODP):
dist_shmem_linux_SOURCES = shmem_linux.c
shmem_linux_LDFLAGS = $(AM_LDFLAGS) -lrt

#shmem_odp is the odp part:
dist_shmem_odp_SOURCES = shmem_odp.c
shmem_odp_CFLAGS = $(AM_CFLAGS) \
		   $(INCCUNIT_COMMON) \
		   $(INCODP)
shmem_odp_LDFLAGS = $(AM_LDFLAGS)
shmem_odp_LDADD = $(LIBCUNIT_COMMON) $(LIBODP)

noinst_HEADERS = shmem_common.h shmem_linux.h shmem_odp.h
