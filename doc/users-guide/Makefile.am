include ../Makefile.inc

SRC    = $(top_srcdir)/doc/users-guide/users-guide.adoc \
	 $(top_srcdir)/doc/users-guide/users-guide-cls.adoc \
	 $(top_srcdir)/doc/users-guide/users-guide-pktio.adoc \
	 $(top_srcdir)/doc/users-guide/users-guide-tm.adoc
TARGET = users-guide.html
IMAGES = $(top_srcdir)/doc/images/overview.svg \
	 $(top_srcdir)/doc/images/atomic_queue.svg \
	 $(top_srcdir)/doc/images/odp_components.svg \
	 $(top_srcdir)/doc/images/ODP-Logo-HQ.svg \
	 $(top_srcdir)/doc/images/odp_rx_processing.svg \
	 $(top_srcdir)/doc/images/odp_scheduling.svg \
	 $(top_srcdir)/doc/images/odp_traffic_manager.svg \
	 $(top_srcdir)/doc/images/ordered_queue.svg \
	 $(top_srcdir)/doc/images/packet.svg \
	 $(top_srcdir)/doc/images/parallel_queue.svg \
	 $(top_srcdir)/doc/images/pktin_direct_recv.svg \
	 $(top_srcdir)/doc/images/pktin_queue_recv.svg \
	 $(top_srcdir)/doc/images/pktin_sched_recv.svg \
	 $(top_srcdir)/doc/images/pktio_fsm.svg \
	 $(top_srcdir)/doc/images/pktout_direct_send.svg \
	 $(top_srcdir)/doc/images/pktout_queue_send.svg \
	 $(top_srcdir)/doc/images/release_git.svg \
	 $(top_srcdir)/doc/images/segment.svg \
	 $(top_srcdir)/doc/images/simple_release_git.svg \
	 $(top_srcdir)/doc/images/tm_hierarchy.svg \
	 $(top_srcdir)/doc/images/tm_node.svg

if HAVE_MSCGEN
IMAGES += $(top_srcdir)/doc/images/resource_management.svg
endif

EXTRA_DIST = $(SRC) $(IMAGES)

doc_DATA = $(TARGET)
$(TARGET): $(SRC)

clean-local:
	rm -f $(builddir)/$(TARGET)

$(SRC): $(IMAGES)
