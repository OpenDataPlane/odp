if test_vald
    SUBDIRS = api
# driver tests use internal symbols from libodp-linux which are
# not available when linking with libodp-linux.so
if STATIC_APPS
    SUBDIRS += drv
endif
endif
