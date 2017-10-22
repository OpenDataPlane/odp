ODP_INCLUDES = \
	-I$(top_builddir)/platform/@with_platform@/include \
	-I$(top_srcdir)/platform/@with_platform@/include \
	-I$(top_srcdir)/platform/@with_platform@/arch/@ARCH_DIR@ \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/include

if ODP_ABI_COMPAT
ODP_INCLUDES += \
	-I$(top_srcdir)/include/odp/arch/@ARCH_ABI@
endif

HELPER_INCLUDES = \
	-I$(top_srcdir)/helper/include

LIB   = $(top_builddir)/lib
