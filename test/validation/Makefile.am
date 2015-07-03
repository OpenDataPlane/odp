AM_CFLAGS += -I$(srcdir)/common
AM_LDFLAGS += -static

ODP_CU_COMMON=common/odp_cunit_common.c

odp_crypto_CFLAGS = $(AM_CFLAGS) -I$(srcdir)/crypto

ODP_MODULES = buffer \
	      classification \
	      cpumask \
	      crypto \
	      errno \
	      init \
	      queue \
	      packet \
	      pktio \
	      pool \
	      random \
	      scheduler \
	      synchronizers \
	      thread \
	      time \
	      timer \
	      shmem \
	      system

SUBDIRS = common $(ODP_MODULES)
