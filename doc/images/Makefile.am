.svg.png:
	convert $^ $@

.svg.eps:
	convert $^ $@

.msc.png:
	mscgen -T png -i $^ -o $@

SVG_SRCS = \
	atomic_queue.svg \
	ordered_queue.svg \
	parallel_queue.svg \
	odp_components.svg \
	odp_rx_processing.svg \
	odp_scheduling.svg \
	odp_traffic_manager.svg \
	overview.svg \
	release_git.svg \
	simple_release_git.svg

SVG_TARGETS = $(SVG_SRCS:svg=png)
SVG_TARGETS += $(SVG_SRCS:svg=eps)

MSG_SRCS = resource_management.msc
MSG_TARGETS = $(MSG_SRCS:msc=png)

EXTRA_DIST = $(SVG_SRCS) $(MSG_SRCS)

TARGETS=$(SVG_TARGETS) $(MSG_TARGETS)

if HAVE_IMAGEMAGIC
TARGETS += $(SVG_TARGETS)
endif

if HAVE_MSCGEN
TARGETS += $(MSG_TARGETS)
endif

all-local: $(TARGETS)

clean-local:
	rm -f $(SVG_TARGETS) $(MSG_TARGETS)
