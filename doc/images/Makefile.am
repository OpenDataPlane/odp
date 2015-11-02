SVG_SRCS =  atomic_queue.svg \
	ordered_queue.svg \
	parallel_queue.svg
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

resource_management.png: resource_management.msc
	mscgen -T png -i $< -o $@
