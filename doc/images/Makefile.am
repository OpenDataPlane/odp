SVG_SRCS =  atomic_queue.svg \
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

TARGETS=

if HAVE_IMAGEMAGIC
TARGETS += $(SVG_TARGETS)
endif

if HAVE_MSCGEN
TARGETS += $(MSG_TARGETS)
endif

all-local: $(TARGETS)

clean-local:
	rm -f $(SVG_TARGETS) $(MSG_TARGETS)

atomic_queue.png: atomic_queue.svg
	convert $< $@
atomic_queue.eps: atomic_queue.svg
	convert $< $@

ordered_queue.png: ordered_queue.svg
	convert $< $@
parallel_queue.eps: parallel_queue.svg
	convert $< $@

parallel_queue.png: parallel_queue.svg
	convert $< $@
ordered_queue.eps: ordered_queue.svg
	convert $< $@

odp_components.png: odp_components.svg
	convert $< $@
odp_components.eps: odp_components.svg
	convert $< $@

odp_rx_processing.png: odp_rx_processing.svg
	convert $< $@
odp_rx_processing.eps: odp_rx_processing.svg
	convert $< $@

odp_scheduling.png: odp_scheduling.svg
	convert $< $@
odp_scheduling.eps: odp_scheduling.svg
	convert $< $@

odp_traffic_manager.png: odp_traffic_manager.svg
	convert $< $@
odp_traffic_manager.eps: odp_traffic_manager.svg
	convert $< $@

overview.png: overview.svg
	convert $< $@
overview.eps: overview.svg

release_git.png: release_git.svg
	convert $< $@
release_git.eps: release_git.svg
	convert $< $@

simple_release_git.png: simple_release_git.svg
	convert $< $@
simple_release_git.eps: simple_release_git.svg
	convert $< $@

resource_management.png: resource_management.msc
	mscgen -T png -i $< -o $@
