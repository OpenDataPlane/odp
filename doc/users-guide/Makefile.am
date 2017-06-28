include ../Makefile.inc

SRC    = $(top_srcdir)/doc/users-guide/users-guide.adoc \
	 $(top_srcdir)/doc/users-guide/users-guide-cls.adoc \
	 $(top_srcdir)/doc/users-guide/users-guide-crypto.adoc \
	 $(top_srcdir)/doc/users-guide/users-guide-packet.adoc \
	 $(top_srcdir)/doc/users-guide/users-guide-pktio.adoc \
	 $(top_srcdir)/doc/users-guide/users-guide-timer.adoc \
	 $(top_srcdir)/doc/users-guide/users-guide-tm.adoc
TARGET = users-guide.html
IMAGES = $(IMAGES_DIR)/overview.svg \
	 $(IMAGES_DIR)/atomic_queue.svg \
	 $(IMAGES_DIR)/odp_components.svg \
	 $(IMAGES_DIR)/ODP-Logo-HQ.svg \
	 $(IMAGES_DIR)/odp_rx_processing.svg \
	 $(IMAGES_DIR)/odp_scheduling.svg \
	 $(IMAGES_DIR)/odp_traffic_manager.svg \
	 $(IMAGES_DIR)/ordered_queue.svg \
	 $(IMAGES_DIR)/packet_flow.svg \
	 $(IMAGES_DIR)/packet-adddata.svg \
	 $(IMAGES_DIR)/packet-align.svg \
	 $(IMAGES_DIR)/packet-copyops.svg \
	 $(IMAGES_DIR)/packet-remdata.svg \
	 $(IMAGES_DIR)/packet-split.svg \
	 $(IMAGES_DIR)/packet.svg \
	 $(IMAGES_DIR)/parallel_queue.svg \
	 $(IMAGES_DIR)/pktin_direct_recv.svg \
	 $(IMAGES_DIR)/pktin_queue_recv.svg \
	 $(IMAGES_DIR)/pktin_sched_recv.svg \
	 $(IMAGES_DIR)/pktio_fsm.svg \
	 $(IMAGES_DIR)/pktout_direct_send.svg \
	 $(IMAGES_DIR)/pktout_queue_send.svg \
	 $(IMAGES_DIR)/release_git.svg \
	 $(IMAGES_DIR)/segment.svg \
	 $(IMAGES_DIR)/simple_release_git.svg \
	 $(IMAGES_DIR)/timeout_fsm.svg \
	 $(IMAGES_DIR)/timer_fsm.svg \
	 $(IMAGES_DIR)/tm_hierarchy.svg \
	 $(IMAGES_DIR)/tm_node.svg \
	 $(IMAGES_DIR)/pktin_sched_cls.svg

if HAVE_MSCGEN
IMAGES += $(IMAGES_DIR)/resource_management.svg
endif

EXTRA_DIST = $(SRC) $(IMAGES)

doc_DATA = $(TARGET)
$(TARGET): $(SRC) $(IMAGES)

clean-local:
	rm -f $(builddir)/$(TARGET)

$(SRC): $(IMAGES)
