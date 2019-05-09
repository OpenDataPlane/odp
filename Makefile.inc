ODP_INCLUDES = \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/include

if ODP_ABI_COMPAT
ODP_INCLUDES += \
	-I$(top_srcdir)/include/odp/arch/@ARCH_ABI@
else
ODP_INCLUDES += \
	-I$(top_srcdir)/platform/@with_platform@/include \
	-I$(top_srcdir)/platform/@with_platform@/arch/@ARCH_DIR@ \
	-I$(top_srcdir)/platform/@with_platform@/arch/default \
	-I$(top_srcdir)/platform/@with_platform@/include-abi
endif

HELPER_INCLUDES = \
	-I$(top_builddir)/helper/include \
	-I$(top_srcdir)/helper/include

LIB   = $(top_builddir)/lib
