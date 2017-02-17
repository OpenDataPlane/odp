include ../Makefile.inc

#the main test program is shmem_linux, which, in turn, starts a shmem_odp:
test_PROGRAMS = shmem_linux$(EXEEXT)
test_extra_PROGRAMS = shmem_odp1$(EXEEXT) shmem_odp2$(EXEEXT)
test_extradir = $(testdir)

#shmem_linux is stand alone, pure linux (no ODP):
dist_shmem_linux_SOURCES = shmem_linux.c
shmem_linux_LDFLAGS = $(AM_LDFLAGS) -lrt

#shmem_odp1 and shmem_odp2 are the 2 ODP processes:
dist_shmem_odp1_SOURCES = shmem_odp1.c
shmem_odp1_CFLAGS = $(AM_CFLAGS) \
		   $(INCCUNIT_COMMON) \
		   $(INCODP)
shmem_odp1_LDFLAGS = $(AM_LDFLAGS)
shmem_odp1_LDADD = $(LIBCUNIT_COMMON) $(LIBODP)

dist_shmem_odp2_SOURCES = shmem_odp2.c
shmem_odp2_CFLAGS = $(AM_CFLAGS) \
		   $(INCCUNIT_COMMON) \
		   $(INCODP)
shmem_odp2_LDFLAGS = $(AM_LDFLAGS)
shmem_odp2_LDADD = $(LIBCUNIT_COMMON) $(LIBODP)


noinst_HEADERS = shmem_common.h shmem_linux.h shmem_odp1.h shmem_odp2.h
