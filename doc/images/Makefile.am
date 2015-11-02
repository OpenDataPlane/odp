SVG_SRCS =  atomic_queue.svg \
	ordered_queue.svg \
	parallel_queue.svg
SVG_TARGETS = $(SVG_SRCS:svg=png)
SVG_TARGETS += $(SVG_SRCS:svg=eps)

EXTRA_DIST = $(SVG_SRCS)

TARGETS=

if HAVE_IMAGEMAGIC
TARGETS += $(SVG_TARGETS)
endif

all-local: $(TARGETS)

clean-local:
	rm -f $(TARGETS)

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
