#!/bin/bash
# check-xdp-deps.sh — verify the Phase-2 (XDP/eBPF) build toolchain.
#
# ubridge's XDP dataplane needs: clang (bpf target), libbpf (dev), bpftool,
# libelf (dev), zlib (dev). This probes for each (looking in /usr/sbin too —
# openSUSE puts bpftool there, off a non-root PATH) and, on any miss, prints the
# exact install command for the detected distro. Used by `make check-xdp`.
#
# Exits 0 if the toolchain is usable, 1 otherwise.
set -u
miss=()

# --- clang with the bpf target ---
CLANG=""
for c in clang clang-22 clang-21 clang-20 clang-19 clang-18; do
    if command -v "$c" >/dev/null 2>&1 && \
       echo 'struct xdp_md; int x(struct xdp_md *p){return 0;}' \
         | "$c" -target bpf -O2 -c -x c - -o /dev/null 2>/dev/null; then
        CLANG="$c"; break
    fi
done
[ -n "$CLANG" ] || miss+=("clang (with -target bpf)")

# --- bpftool (command -v misses /usr/sbin on a stripped PATH) ---
BPFTOOL=""
for p in "$(command -v bpftool 2>/dev/null)" /usr/sbin/bpftool /sbin/bpftool /usr/bin/bpftool; do
    [ -x "$p" ] && BPFTOOL="$p" && break
done
[ -n "$BPFTOOL" ] || miss+=("bpftool")

# --- libbpf (pkg-config, else the header) ---
LIBBPF_VER=""
if pkg-config --exists libbpf 2>/dev/null; then
    LIBBPF_VER="$(pkg-config --modversion libbpf)"
elif [ -f /usr/include/bpf/libbpf.h ]; then
    LIBBPF_VER="(header present, no pkg-config)"
else
    miss+=("libbpf (devel)")
fi

# --- libelf / zlib (link deps of libbpf) ---
{ pkg-config --exists libelf 2>/dev/null || [ -f /usr/include/libelf.h ]; } || miss+=("libelf (devel)")
{ pkg-config --exists zlib   2>/dev/null || [ -f /usr/include/zlib.h ]; }   || miss+=("zlib (devel)")

if [ ${#miss[@]} -eq 0 ]; then
    echo "[check-xdp] OK  clang=$CLANG  libbpf=$LIBBPF_VER  bpftool=$BPFTOOL"
    exit 0
fi

echo "[check-xdp] MISSING: ${miss[*]}"
distro_id() { ( . /etc/os-release 2>/dev/null && echo "${ID:-unknown}" ) || echo unknown; }
case "$(distro_id)" in
    opensuse*|suse*)
        echo "  sudo zypper install clang libbpf-devel bpftool libelf-devel zlib-devel" ;;
    debian|ubuntu|linuxmint)
        echo "  sudo apt install clang libbpf-dev bpftool libelf-dev zlib1g-dev" ;;
    fedora|rhel|centos|rocky|alma)
        echo "  sudo dnf install clang libbpf-devel bpftool elfutils-libelf-devel zlib-devel" ;;
    arch|manjaro|garuda)
        echo "  sudo pacman -S clang libbpf bpftool libelf zlib" ;;
    *)
        echo "  install: clang (bpf target), libbpf (devel), bpftool, libelf (devel), zlib (devel)" ;;
esac
exit 1
