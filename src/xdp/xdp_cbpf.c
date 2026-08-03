/* xdp_cbpf.c — pcap front-end: compile a tcpdump expression to classic BPF.
 *
 * The only translation unit that includes <pcap/pcap.h> (see xdp_cbpf.h). Same
 * call ubridge's packet_filter.c makes for the mark/bpf filters, same DLT_EN10MB
 * link type. The cBPF stream is handed to xdp_translate.c, which turns it into
 * eBPF. */
#define _GNU_SOURCE
#include <string.h>
#include <pcap/pcap.h>

#include "xdp_cbpf.h"

/* Our insn must be byte-identical to libpcap's compiled insn. */
_Static_assert(sizeof(struct ub_cbpf_insn) == sizeof(struct bpf_insn),
               "ub_cbpf_insn must match libpcap bpf_insn layout");

int cbpf_compile(const char *expr, struct ub_cbpf_insn *out, int max_insns,
                 char *errbuf, int errlen)
{
    pcap_t *p;
    struct bpf_program fp;
    int ret = -1;

    p = pcap_open_dead(DLT_EN10MB, 65535);
    if (!p) {
        snprintf(errbuf, errlen, "pcap_open_dead failed");
        return -1;
    }
    if (pcap_compile(p, &fp, expr, 1, PCAP_NETMASK_UNKNOWN) < 0) {
        snprintf(errbuf, errlen, "%s", pcap_geterr(p));
        pcap_close(p);
        return -1;
    }
    pcap_close(p);

    if (fp.bf_len > max_insns) {
        snprintf(errbuf, errlen, "expression compiles to %d insns (max %d)",
                 (int)fp.bf_len, max_insns);
    } else if (fp.bf_len > 0) {
        memcpy(out, fp.bf_insns, (size_t)fp.bf_len * sizeof(struct bpf_insn));
        ret = (int)fp.bf_len;
    } else {
        ret = 0;
    }
    pcap_freecode(&fp);
    return ret;
}
