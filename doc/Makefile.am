SUBDIRS = images

if HAVE_DOXYGEN
clean-local:
	rm -rf output
endif

if user_guide
SUBDIRS += implementers-guide users-guide process-guide
endif
