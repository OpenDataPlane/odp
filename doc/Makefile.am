SUBDIRS = images

if HAVE_DOXYGEN
clean-local:
	rm -rf output
endif

if user_guide
SUBDIRS += implementers-guide users-guide process-guide
endif

EXTRA_DIST = \
	     api_guide_lines.dox \
	     examples.dox \
	     images \
	     odp.dox \
	     release.dox
