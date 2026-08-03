#!/usr/bin/make -f
#
#   This file is part of ubridge, a program to bridge network interfaces
#   to UDP tunnels.
#
#   Copyright (C) 2015 GNS3 Technologies Inc.
#
#   ubridge is free software: you can redistribute it and/or modify it
#   under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   ubridge is distributed in the hope that it will be useful, but
#   WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

NAME    =   ubridge

SRC     =   src/ubridge.c               \
            src/nio.c                   \
            src/nio_udp.c               \
            src/nio_unix.c              \
            src/nio_ethernet.c          \
            src/nio_tap.c               \
            src/parse.c                 \
            src/packet_filter.c         \
            src/delay_line.c            \
            src/pcap_capture.c          \
            src/pcap_filter.c           \
            src/hypervisor.c            \
            src/hypervisor_parser.c     \
            src/hypervisor_bridge.c


OBJ     =   $(SRC:.c=.o)

CC      ?=   gcc

CFLAGS  +=   -Wall

BINDIR  =   /usr/local/bin

LIBS =   -lpthread -lpcap -lm

# Linux-only: RAW Ethernet + netlink-backed hypervisor modules
SRC += src/nio_linux_raw.c             \
       src/hypervisor_docker.c         \
       src/hypervisor_iol_bridge.c     \
       src/hypervisor_brctl.c          \
       src/hypervisor_link.c           \
       src/hypervisor_tap.c            \
       src/hypervisor_tc.c             \
       src/hypervisor_capture.c        \
       src/hypervisor_marker.c         \
       src/netlink/nl.c

ifeq ($(SYSTEM_INIPARSER),1)
    CFLAGS += -DUSE_SYSTEM_INIPARSER
    LIBS += -liniparser
else
    SRC += src/iniparser/iniparser.c   \
	   src/iniparser/dictionary.c
endif

##############################

$(NAME)	: $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(NAME) $(OBJ) $(LIBS)

.PHONY: clean bench xdp check-xdp

clean:
	-rm -f $(OBJ)
	-rm -f *~
	-rm -f $(NAME)
	-rm -f $(XDP_OBJ) $(XDP_SKEL) $(XDP_SMOKE) $(XDP_FWD) $(XDP_MARKER)

all	: $(NAME)

# Native high-rate data-plane benchmark for the `mark` filter (see bench/).
# Python tops out ~130k pps (GIL); this push past it to find ubridge's ceiling.
bench	: bench/marker_bench

bench/marker_bench	: bench/marker_bench.c
	$(CC) -O2 -Wall -Wextra -o bench/marker_bench bench/marker_bench.c -lpthread

##############################
# Phase 2: XDP / eBPF dataplane (see doc/xdp-tap-mode.md).
# The eBPF object is compiled separately (clang -target bpf), turned into a
# libbpf skeleton, and driven by the userspace loader (src/xdp/xdp_load.c).
# TAPs only support generic (SKB-mode) XDP; the loader attaches in that mode.
CLANG    ?= clang
BPFTOOL  ?= $(shell command -v bpftool 2>/dev/null || echo /usr/sbin/bpftool)
ARCH     := $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/')

XDP_DIR   = src/xdp
XDP_OBJ   = $(XDP_DIR)/ubridge_xdp.bpf.o
XDP_SKEL  = $(XDP_DIR)/ubridge_xdp.skel.h
XDP_SMOKE = $(XDP_DIR)/xdp_smoke
XDP_FWD   = $(XDP_DIR)/xdp_fwd
XDP_MARKER = $(XDP_DIR)/xdp_marker

# eBPF object (CO-RE not needed yet — this program uses no kernel internals).
$(XDP_OBJ): $(XDP_DIR)/ubridge_xdp.bpf.c
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -Wall -c $< -o $@

# libbpf skeleton, consumed via #include in xdp_load.c.
$(XDP_SKEL): $(XDP_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

# Standalone foundation proof (increment A); links libbpf.
$(XDP_SMOKE): $(XDP_SKEL) $(XDP_DIR)/xdp_load.c $(XDP_DIR)/xdp_smoke.c $(XDP_DIR)/xdp_load.h
	$(CC) $(CFLAGS) -I$(XDP_DIR) -o $@ $(XDP_DIR)/xdp_load.c $(XDP_DIR)/xdp_smoke.c -lbpf -lelf -lz

# Forwarding proof (increment B): DEVMAP egress redirect between two taps.
$(XDP_FWD): $(XDP_SKEL) $(XDP_DIR)/xdp_load.c $(XDP_DIR)/xdp_fwd.c $(XDP_DIR)/xdp_load.h
	$(CC) $(CFLAGS) -I$(XDP_DIR) -o $@ $(XDP_DIR)/xdp_load.c $(XDP_DIR)/xdp_fwd.c -lbpf -lelf -lz

# Marker proof (increment C1): ingress tx-marker -> ringbuf -> MARK line -> sink.
$(XDP_MARKER): $(XDP_SKEL) $(XDP_DIR)/xdp_load.c $(XDP_DIR)/xdp_marker.c $(XDP_DIR)/xdp_load.h $(XDP_DIR)/xdp_events.h
	$(CC) $(CFLAGS) -I$(XDP_DIR) -o $@ $(XDP_DIR)/xdp_load.c $(XDP_DIR)/xdp_marker.c -lbpf -lelf -lz -lpthread

xdp: $(XDP_SMOKE) $(XDP_FWD) $(XDP_MARKER)

# Verify the eBPF toolchain is present; prints a distro install line if not.
check-xdp:
	@bash scripts/check-xdp-deps.sh

install : $(NAME)
	chmod +x $(NAME)
	cp -p $(NAME) $(BINDIR)
	setcap cap_net_admin,cap_net_raw=ep $(BINDIR)/$(NAME)
