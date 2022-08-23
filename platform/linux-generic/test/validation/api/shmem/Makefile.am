include ../Makefile.inc

#the main test program is shmem_linux, which, in turn, starts a shmem_odp:
test_PROGRAMS = shmem_linux shmem_odp1 shmem_odp2

#shmem_linux is stand alone, pure linux (no ODP):
shmem_linux_SOURCES = shmem_linux.c shmem_linux.h shmem_common.h
shmem_linux_LDFLAGS =
shmem_linux_LDADD =

#shmem_odp1 and shmem_odp2 are the 2 ODP processes:
shmem_odp1_SOURCES = shmem_odp1.c shmem_odp1.h shmem_common.h

shmem_odp2_SOURCES = shmem_odp2.c shmem_odp2.h shmem_common.h
