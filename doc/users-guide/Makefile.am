include ../Makefile.inc

SRC    = $(top_srcdir)/doc/users-guide/users-guide.adoc
TARGET = users-guide.html
IMAGES = $(top_srcdir)/doc/images/overview.svg \
	 $(top_srcdir)/doc/images/odp_components.svg \
	 $(top_srcdir)/doc/images/odp_rx_processing.svg \
	 $(top_srcdir)/doc/images/odp_scheduling.svg \
	 $(top_srcdir)/doc/images/odp_traffic_manager.svg \
	 $(top_srcdir)/doc/images/parallel_queue.svg \
	 $(top_srcdir)/doc/images/atomic_queue.svg \
	 $(top_srcdir)/doc/images/ordered_queue.svg

IMAGES += $(top_srcdir)/doc/images/pktio_fsm.svg

if HAVE_MSCGEN
IMAGES += $(top_srcdir)/doc/images/resource_management.svg
endif

EXTRA_DIST = $(SRC) $(IMAGES)

doc_DATA = $(TARGET)
$(TARGET): $(SRC)

clean-local:
	rm -f $(builddir)/$(TARGET)

$(SRC): $(IMAGES)
