include ../Makefile.inc

#the main test program is shmem_linux, which, in turn, starts a shmem_odp:
test_PROGRAMS = shmem_linux$(EXEEXT) shmem_odp1$(EXEEXT) shmem_odp2$(EXEEXT)

#shmem_linux is stand alone, pure linux (no ODP):
shmem_linux_SOURCES = shmem_linux.c shmem_linux.h shmem_common.h
shmem_linux_CFLAGS = $(AM_CFLAGS) -I$(top_builddir)/include
shmem_linux_LDFLAGS = $(AM_LDFLAGS) -lrt

#shmem_odp1 and shmem_odp2 are the 2 ODP processes:
shmem_odp1_SOURCES = shmem_odp1.c shmem_odp1.h shmem_common.h
shmem_odp1_CFLAGS = $(AM_CFLAGS) \
		   $(INCCUNIT_COMMON) \
		   $(INCODP)
shmem_odp1_LDFLAGS = $(AM_LDFLAGS)
shmem_odp1_LDADD = $(LIBCUNIT_COMMON) $(LIBODP)

shmem_odp2_SOURCES = shmem_odp2.c shmem_odp2.h shmem_common.h
shmem_odp2_CFLAGS = $(AM_CFLAGS) \
		   $(INCCUNIT_COMMON) \
		   $(INCODP)
shmem_odp2_LDFLAGS = $(AM_LDFLAGS)
shmem_odp2_LDADD = $(LIBCUNIT_COMMON) $(LIBODP)
