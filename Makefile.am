ACLOCAL_AMFLAGS=-I m4
AM_DISTCHECK_CONFIGURE_FLAGS = --enable-user-guides	\
			       --enable-helper-linux	\
			       --with-testdir

if PLATFORM_IS_LINUX_GENERIC
PLATFORM_DIR = platform/linux-generic
PLATFORM_DUMPCONF_DIR = platform/linux-generic/dumpconfig
PLATFORM_TEST_DIR = platform/linux-generic/test
endif

SUBDIRS = \
	  include \
	  $(PLATFORM_DIR) \
	  $(PLATFORM_DUMPCONF_DIR) \
	  helper \
	  doc

if WITH_EXAMPLES
SUBDIRS += example
endif

if WITH_TESTS
SUBDIRS += test
SUBDIRS += helper/test
SUBDIRS += $(PLATFORM_TEST_DIR)
endif

@DX_RULES@

EXTRA_DIST = bootstrap CHANGELOG config/README

distcheck-hook:
	if test -n "$(DX_CLEANFILES)" ; \
	then \
		$(MAKE) doxygen-doc ; \
	fi
