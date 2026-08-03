/* xdp_translate.c — translate compiled cBPF to eBPF, following the kernel's
 * bpf_convert_filter() (net/core/filter.c) register mapping + opcode patterns.
 * LD_ABS/IND use XDP packet reads (the kernel's BPF_LD_ABS insn is socket-only).
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <linux/bpf.h>
#include "xdp_translate.h"

/* classic-BPF constants not in <linux/bpf.h> */
#ifndef BPF_A
# define BPF_A 0x10
#endif
#ifndef BPF_TAX
# define BPF_TAX 0x00
#endif
#ifndef BPF_TXA
# define BPF_TXA 0x80
#endif

/* ---- eBPF helpers (sparse; the kernel's include/uapi/linux/bpf.h has more) ---- */
#define BPF_ALU32_IMM(OP, DST, IMM) \
	((struct bpf_insn){ BPF_ALU|BPF_OP(OP)|BPF_K,.dst_reg=DST,.src_reg=0,.off=0,.imm=IMM })
#define BPF_ALU32_REG(OP, DST, SRC) \
	((struct bpf_insn){ BPF_ALU|BPF_OP(OP)|BPF_X,.dst_reg=DST,.src_reg=SRC,.off=0,.imm=0 })
#define BPF_ALU64_IMM(OP, DST, IMM) \
	((struct bpf_insn){ BPF_ALU64|BPF_OP(OP)|BPF_K,.dst_reg=DST,.src_reg=0,.off=0,.imm=IMM })
#define BPF_ALU64_REG(OP, DST, SRC) \
	((struct bpf_insn){ BPF_ALU64|BPF_OP(OP)|BPF_X,.dst_reg=DST,.src_reg=SRC,.off=0,.imm=0 })
#define BPF_MOV32_IMM(DST, IMM) BPF_ALU32_IMM(BPF_MOV, DST, IMM)
#define BPF_MOV64_REG(DST, SRC) BPF_ALU64_REG(BPF_MOV, DST, SRC)
#define BPF_MOV64_IMM(DST, IMM) \
	((struct bpf_insn){ BPF_ALU64|BPF_MOV|BPF_K,.dst_reg=DST,.src_reg=0,.off=0,.imm=IMM })
#define BPF_JMP_IMM(OP, DST, IMM, OFF) \
	((struct bpf_insn){ BPF_JMP|OP|BPF_K,.dst_reg=DST,.src_reg=0,.off=OFF,.imm=IMM })
#define BPF_JMP_REG(OP, DST, SRC, OFF) \
	((struct bpf_insn){ BPF_JMP|OP|BPF_X,.dst_reg=DST,.src_reg=SRC,.off=OFF,.imm=0 })
#define BPF_JMP_A(OFF) \
	((struct bpf_insn){ BPF_JMP|BPF_JA,0,0,.off=OFF,.imm=0 })
#define XBPF_EXIT() \
	((struct bpf_insn){ BPF_JMP|BPF_EXIT,0,0,0,0 })
#define XBPF_CALL(FUNC) \
	((struct bpf_insn){ BPF_JMP|BPF_CALL,0,0,0,FUNC })
#define BPF_LDX_MEM(SZ, DST, SRC, OFF) \
	((struct bpf_insn){ BPF_LDX|BPF_SIZE(SZ)|BPF_MEM,.dst_reg=DST,.src_reg=SRC,.off=OFF,.imm=0 })
#define BPF_STX_MEM(SZ, DST, SRC, OFF) \
	((struct bpf_insn){ BPF_STX|BPF_SIZE(SZ)|BPF_MEM,.dst_reg=DST,.src_reg=SRC,.off=OFF,.imm=0 })
#define BPF_ST_MEM(SZ, DST, OFF, IMM) \
	((struct bpf_insn){ BPF_ST|BPF_SIZE(SZ)|BPF_MEM,.dst_reg=DST,.src_reg=0,.off=OFF,.imm=IMM })
#define BPF_ENDIAN(FROM, DST, BITS) \
	((struct bpf_insn){ BPF_ALU|BPF_END|BPF_SRC(FROM),.dst_reg=DST,.src_reg=0,.off=0,.imm=BITS })

/* ---- register mapping (kernel's bpf_convert_filter) ---- */
enum { R_A = 0,       /* classic A, also return value */
       R_X = 7,       /* classic X                     */
       R_CTX = 6,     /* ctx (cached from r1)          */
       R_D = 8,       /* packet data (if seen_ld_abs)  */
       R_END = 9,     /* data_end                      */
       R_TMP = 4,     /* internal temp                 */
       R_FP = 10 };

/* helper func IDs */
enum { FN_map_update_elem = 2, FN_tail_call = 12 };

/* forward jumps that we back-patch */
struct fixup { int insn_idx; int target_cbpf_pc; int is_done; };

#define INSNS 4096
struct ebbuf {
    struct bpf_insn insns[INSNS];
    int n;
    int addrs[512];          /* cbpf pc -> ebpf insn index, or -1 */
    struct fixup fixups[INSNS];
    int n_fixups;
    int done_fixups[INSNS];
    int n_done;
};

static struct bpf_insn *emit(struct ebbuf *b, struct bpf_insn i) {
    b->insns[b->n] = i; return &b->insns[b->n++];
}
/* emit BPF_LD_MAP_FD as two insns (the kernel's 1:2 pseudo-insn) */
static void emit_ld_map_fd(struct ebbuf *b, int dst, int fd) {
    emit(b, (struct bpf_insn){ BPF_LD|BPF_DW|BPF_IMM,
        .dst_reg = dst, .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = fd });
    emit(b, (struct bpf_insn){ 0, 0, 0, 0, 0 });
}

/* ---- epilogue: write R0(match) to scratch, tail_call prog_array[1] -------- */
static void emit_epilogue(struct ebbuf *b, int scratch_fd, int prog_array_fd)
{
    /* key = 0 (FP-4); val = R0 (FP-8) */
    emit(b, BPF_ST_MEM(BPF_W, R_FP, -4, 0));
    emit(b, BPF_STX_MEM(BPF_W, R_FP, R_A, -8));

    /* map_update_elem(scratch, &key(FP-4), &val(FP-8), BPF_ANY) */
    emit_ld_map_fd(b, 1, scratch_fd);
    emit(b, BPF_MOV64_REG(2, R_FP));
    emit(b, BPF_ALU64_IMM(BPF_ADD, 2, -4));
    emit(b, BPF_MOV64_REG(3, R_FP));
    emit(b, BPF_ALU64_IMM(BPF_ADD, 3, -8));
    emit(b, BPF_MOV32_IMM(4, 0));
    emit(b, XBPF_CALL(FN_map_update_elem));

    /* tail_call(ctx, prog_array, 1) */
    emit(b, BPF_MOV64_REG(1, R_CTX));
    emit_ld_map_fd(b, 2, prog_array_fd);
    emit(b, BPF_MOV32_IMM(3, 1));
    emit(b, XBPF_CALL(FN_tail_call));

    /* fallthrough -> XDP_PASS */
    emit(b, BPF_MOV32_IMM(R_A, 2));
    emit(b, XBPF_EXIT());
}

/* ---- ABS packet load (constant offset k) ----------------------------------- */
static void ld_abs(struct ebbuf *b, int sz, int k)
{
    /* R_TMP = data; R_TMP += k */
    emit(b, BPF_MOV64_REG(R_TMP, R_D));       /* r4 = data (64-bit) */
    emit(b, BPF_ALU64_IMM(BPF_ADD, R_TMP, k)); /* r4 += k */

    /* bounds: if (r4 + sz > data_end) goto nomatch */
    emit(b, BPF_MOV64_REG(1, R_TMP));
    emit(b, BPF_ALU64_IMM(BPF_ADD, 1, sz));
    emit(b, BPF_JMP_REG(BPF_JGT, 1, R_END, 0));  /* placeholder off */
    b->done_fixups[b->n_done++] = b->n - 1;       /* OOB -> epilogue */

    /* load */
    emit(b, BPF_LDX_MEM(sz == 4 ? BPF_W : sz == 2 ? BPF_H : BPF_B,
                         R_A, R_TMP, 0));

    /* byte swap for W/H */
    if (sz == 4) emit(b, BPF_ENDIAN(BPF_TO_LE, R_A, 32));
    else if (sz == 2) emit(b, BPF_ENDIAN(BPF_TO_LE, R_A, 16));
}

/* ---- IND packet load (offset X + k) ---------------------------------------- */
static void ld_ind(struct ebbuf *b, int sz, int k)
{
    /* R_TMP = data; R_TMP += R7(X); R_TMP += k */
    /* NB: R7 is 32-bit; ALU64_ADD uses full 64-bit register (upper 32 are 0
     * because X is moved/set with MOV32 which zero-extends). */
    emit(b, BPF_MOV64_REG(R_TMP, R_D));
    emit(b, BPF_ALU64_REG(BPF_ADD, R_TMP, R_X));
    emit(b, BPF_ALU64_IMM(BPF_ADD, R_TMP, k));

    /* bounds */
    emit(b, BPF_MOV64_REG(1, R_TMP));
    emit(b, BPF_ALU64_IMM(BPF_ADD, 1, sz));
    emit(b, BPF_JMP_REG(BPF_JGT, 1, R_END, 0));
    b->done_fixups[b->n_done++] = b->n - 1;

    emit(b, BPF_LDX_MEM(sz == 4 ? BPF_W : sz == 2 ? BPF_H : BPF_B,
                         R_A, R_TMP, 0));

    if (sz == 4) emit(b, BPF_ENDIAN(BPF_TO_LE, R_A, 32));
    else if (sz == 2) emit(b, BPF_ENDIAN(BPF_TO_LE, R_A, 16));
}

/* ---- JMP emission, following the kernel's 3 cases --------------------------
 * Each call emits 1 or 2 eBPF insns and records fixups for the cbpf targets. */
static void emit_jmp(struct ebbuf *b, int pc, const struct ub_cbpf_insn *fp)
{
    int jt = fp->jt, jf = fp->jf, op = BPF_OP(fp->code);
    int src = BPF_SRC(fp->code);  /* BPF_K=0 or BPF_X=0x08 */
    int imm = fp->k;
    int target;
    struct bpf_insn insn;

    /* Case 1: jf == 0 — "on false, fall through"; only a conditional to target_t */
    if (jf == 0) {
        target = pc + jt + 1;
        insn = (struct bpf_insn){
            BPF_JMP | op | src, .dst_reg = R_A,
            .src_reg = (src == BPF_X) ? R_X : 0,
            .off = 0, .imm = imm };
        emit(b, insn);
        b->fixups[b->n_fixups++] = (struct fixup){b->n - 1, target, 0};
        /* fall-through goes to next cBPF insn (pc+1) */
        return;
    }

    /* Case 2: jt == 0 — "on true, fall through"; emit inverted conditional to target_f */
    if (jt == 0) {
        int inv_op;
        switch (op) {
        case BPF_JEQ:  inv_op = BPF_JNE;  break;
        case BPF_JGT:  inv_op = BPF_JLE;  break;
        case BPF_JGE:  inv_op = BPF_JLT;  break;
        default: /* JSET has no direct inverse, fall to case 3 */
            goto two_insn;
        }
        target = pc + jf + 1;
        insn = (struct bpf_insn){
            BPF_JMP | inv_op | src, .dst_reg = R_A,
            .src_reg = (src == BPF_X) ? R_X : 0,
            .off = 0, .imm = imm };
        emit(b, insn);
        b->fixups[b->n_fixups++] = (struct fixup){b->n - 1, target, 0};
        return;
    }

two_insn:
    /* Case 3: both jt and jf != 0 — Jxx to target_t; JA to target_f */
    target = pc + jt + 1;
    insn = (struct bpf_insn){
        BPF_JMP | op | src, .dst_reg = R_A,
        .src_reg = (src == BPF_X) ? R_X : 0,
        .off = 0, .imm = imm };
    emit(b, insn);
    b->fixups[b->n_fixups++] = (struct fixup){b->n - 1, target, 0};

    target = pc + jf + 1;
    emit(b, BPF_JMP_A(0));
    b->fixups[b->n_fixups++] = (struct fixup){b->n - 1, target, 0};
}

/* ---- DIV/MOD-X zero guard (kernel emits an exception path) ----------------- */
static void emit_divmod_x_guard(struct ebbuf *b)
{
    /* if R_X != 0 goto ok; R_A = 0; exit -> goto epilogue (done) */
    emit(b, BPF_JMP_IMM(BPF_JNE, R_X, 0, 2));  /* skip next 2 if X!=0 */
    emit(b, BPF_ALU32_REG(BPF_XOR, R_A, R_A));  /* A = 0 */
    emit(b, BPF_JMP_A(0));                      /* goto epilogue */
    b->done_fixups[b->n_done++] = b->n - 1;
}

/* ---- main translation ------------------------------------------------------ */
int cbpf_translate(const struct ub_cbpf_insn *cbpf, int len,
                   int scratch_fd, int prog_array_fd,
                   struct bpf_insn **out, int *out_len,
                   char *errbuf, int errlen)
{
    struct ebbuf b;
    int i, target, stack_off, seen_ld_abs = 0;
    (void)errlen;

    if (len <= 0 || len > 512) {
        snprintf(errbuf, errlen, "bad cBPF length %d", len); return -1;
    }

    memset(&b, 0, sizeof(b));
    memset(b.addrs, 0xff, sizeof(b.addrs));

    /* ---- prologue ---- */
    /* Classic BPF expects A and X zeroed first (kernel does XOR A,A; XOR X,X) */
    emit(&b, BPF_ALU32_REG(BPF_XOR, R_A, R_A));
    emit(&b, BPF_ALU32_REG(BPF_XOR, R_X, R_X));
    /* Save ctx in callee-saved R6 */
    emit(&b, BPF_MOV64_REG(R_CTX, 1));

    /* ---- pass 1: emit, recording cbpf-pc->ebpf-offset + fixups ---- */
    for (i = 0; i < len; i++) {
        b.addrs[i] = b.n;  /* record where this cBPF insn starts */

        int code = cbpf[i].code;
        int k    = cbpf[i].k;

        switch (code) {
        /* ---- ALU (kernel maps as-is) ---- */
        case BPF_ALU|BPF_ADD|BPF_X:
        case BPF_ALU|BPF_ADD|BPF_K:
        case BPF_ALU|BPF_SUB|BPF_X:
        case BPF_ALU|BPF_SUB|BPF_K:
        case BPF_ALU|BPF_AND|BPF_X:
        case BPF_ALU|BPF_AND|BPF_K:
        case BPF_ALU|BPF_OR|BPF_X:
        case BPF_ALU|BPF_OR|BPF_K:
        case BPF_ALU|BPF_XOR|BPF_X:
        case BPF_ALU|BPF_XOR|BPF_K:
        case BPF_ALU|BPF_LSH|BPF_X:
        case BPF_ALU|BPF_LSH|BPF_K:
        case BPF_ALU|BPF_RSH|BPF_X:
        case BPF_ALU|BPF_RSH|BPF_K:
        case BPF_ALU|BPF_MUL|BPF_X:
        case BPF_ALU|BPF_MUL|BPF_K:
        case BPF_ALU|BPF_NEG:
            emit(&b, (struct bpf_insn){
                (__u8)(BPF_ALU | BPF_OP(code) | BPF_SRC(code)),
                .dst_reg = R_A,
                .src_reg = (BPF_SRC(code) == BPF_X) ? R_X : 0,
                .off = 0, .imm = k });
            break;

        case BPF_ALU|BPF_DIV|BPF_X:
        case BPF_ALU|BPF_MOD|BPF_X:
            emit_divmod_x_guard(&b);
            emit(&b, (struct bpf_insn){
                (__u8)(BPF_ALU | BPF_OP(code) | BPF_X),
                .dst_reg = R_A, .src_reg = R_X, .off = 0, .imm = 0 });
            break;

        case BPF_ALU|BPF_DIV|BPF_K:
        case BPF_ALU|BPF_MOD|BPF_K:
            if (k == 0) { emit(&b, BPF_MOV32_IMM(R_A, 0)); }
            else emit(&b, BPF_ALU32_IMM(BPF_OP(code), R_A, k));
            break;

        /* ---- LD ABS/IND (packet) ---- */
        case BPF_LD|BPF_ABS|BPF_W:
            if (!seen_ld_abs) {
                emit(&b, BPF_LDX_MEM(BPF_DW, R_D, R_CTX, 0));   /* data */
                emit(&b, BPF_LDX_MEM(BPF_DW, R_END, R_CTX, 8)); /* data_end */
                seen_ld_abs = 1;
            }
            ld_abs(&b, 4, k); break;
        case BPF_LD|BPF_ABS|BPF_H:
            if (!seen_ld_abs) { emit(&b, BPF_LDX_MEM(BPF_DW, R_D, R_CTX, 0)); emit(&b, BPF_LDX_MEM(BPF_DW, R_END, R_CTX, 8)); seen_ld_abs = 1; }
            ld_abs(&b, 2, k); break;
        case BPF_LD|BPF_ABS|BPF_B:
            if (!seen_ld_abs) { emit(&b, BPF_LDX_MEM(BPF_DW, R_D, R_CTX, 0)); emit(&b, BPF_LDX_MEM(BPF_DW, R_END, R_CTX, 8)); seen_ld_abs = 1; }
            ld_abs(&b, 1, k); break;
        case BPF_LD|BPF_IND|BPF_W:
            if (!seen_ld_abs) { emit(&b, BPF_LDX_MEM(BPF_DW, R_D, R_CTX, 0)); emit(&b, BPF_LDX_MEM(BPF_DW, R_END, R_CTX, 8)); seen_ld_abs = 1; }
            ld_ind(&b, 4, k); break;
        case BPF_LD|BPF_IND|BPF_H:
            if (!seen_ld_abs) { emit(&b, BPF_LDX_MEM(BPF_DW, R_D, R_CTX, 0)); emit(&b, BPF_LDX_MEM(BPF_DW, R_END, R_CTX, 8)); seen_ld_abs = 1; }
            ld_ind(&b, 2, k); break;
        case BPF_LD|BPF_IND|BPF_B:
            if (!seen_ld_abs) { emit(&b, BPF_LDX_MEM(BPF_DW, R_D, R_CTX, 0)); emit(&b, BPF_LDX_MEM(BPF_DW, R_END, R_CTX, 8)); seen_ld_abs = 1; }
            ld_ind(&b, 1, k); break;

        /* ---- JMP ---- */
        case BPF_JMP|BPF_JA:
            target = i + k + 1;
            emit(&b, BPF_JMP_A(0));
            b.fixups[b.n_fixups++] = (struct fixup){b.n - 1, target, 0};
            break;
        case BPF_JMP|BPF_JEQ|BPF_K:
        case BPF_JMP|BPF_JEQ|BPF_X:
        case BPF_JMP|BPF_JGT|BPF_K:
        case BPF_JMP|BPF_JGT|BPF_X:
        case BPF_JMP|BPF_JGE|BPF_K:
        case BPF_JMP|BPF_JGE|BPF_X:
        case BPF_JMP|BPF_JSET|BPF_K:
        case BPF_JMP|BPF_JSET|BPF_X:
            emit_jmp(&b, i, &cbpf[i]);
            break;

        /* ---- LD IMM ---- */
        case BPF_LD|BPF_IMM:
        case BPF_LDX|BPF_IMM:
            emit(&b, BPF_MOV32_IMM((BPF_CLASS(code) == BPF_LD) ? R_A : R_X, k));
            break;

        /* ---- LD / LDX MEM (stack / M[]) ---- */
        case BPF_LD|BPF_MEM:
        case BPF_LDX|BPF_MEM:
            stack_off = k * 4 + 4;
            emit(&b, BPF_LDX_MEM(BPF_W,
                (BPF_CLASS(code) == BPF_LD) ? R_A : R_X,
                R_FP, -stack_off));
            break;

        /* ---- ST / STX to stack ---- */
        case BPF_ST:
        case BPF_STX:
            stack_off = k * 4 + 4;
            emit(&b, BPF_STX_MEM(BPF_W, R_FP,
                (BPF_CLASS(code) == BPF_ST) ? R_A : R_X,
                -stack_off));
            break;

        /* ---- LD / LDX LEN (skb->len → for XDP: data_end - data, kept in a TMP) ---- */
        case BPF_LD|BPF_W|BPF_LEN:
        case BPF_LDX|BPF_W|BPF_LEN:
            if (!seen_ld_abs) {
                emit(&b, BPF_LDX_MEM(BPF_DW, R_D, R_CTX, 0));
                emit(&b, BPF_LDX_MEM(BPF_DW, R_END, R_CTX, 8));
                seen_ld_abs = 1;
            }
            /* R_TMP = data_end - data (u32) */
            emit(&b, BPF_MOV64_REG(R_TMP, R_END));
            emit(&b, BPF_ALU64_REG(BPF_SUB, R_TMP, R_D));
            emit(&b, BPF_MOV64_REG((BPF_CLASS(code)==BPF_LD)?R_A:R_X, R_TMP));
            break;

        /* ---- MSH: ldxb 4*([14]&0xf) ---- */
        case BPF_LDX|BPF_MSH|BPF_B:
            if (!seen_ld_abs) {
                emit(&b, BPF_LDX_MEM(BPF_DW, R_D, R_CTX, 0));
                emit(&b, BPF_LDX_MEM(BPF_DW, R_END, R_CTX, 8));
                seen_ld_abs = 1;
            }
            /* X = A (save A into X temporarily) */
            /* Actually the kernel does: X = A (save), A = *(u8*)(data+K);
             * A &= 0xf; A <<= 2; TMP = X; X = A; A = TMP */
            emit(&b, BPF_MOV64_REG(R_X, R_A));
            ld_abs(&b, 1, k);
            emit(&b, BPF_ALU32_IMM(BPF_AND, R_A, 0xf));
            emit(&b, BPF_ALU32_IMM(BPF_LSH, R_A, 2));
            emit(&b, BPF_MOV64_REG(R_TMP, R_X));
            emit(&b, BPF_MOV64_REG(R_X, R_A));
            emit(&b, BPF_MOV64_REG(R_A, R_TMP));
            break;

        /* ---- RET ---- */
        case BPF_RET|BPF_A:
            /* R0 already holds the return value.  Done. */
            emit(&b, BPF_JMP_A(0));
            b.done_fixups[b.n_done++] = b.n - 1;
            break;
        case BPF_RET|BPF_K:
            emit(&b, BPF_MOV32_IMM(R_A, k));
            emit(&b, BPF_JMP_A(0));
            b.done_fixups[b.n_done++] = b.n - 1;
            break;

        /* ---- MISC (TAX / TXA) ---- */
        case BPF_MISC|BPF_TAX:
            emit(&b, BPF_MOV64_REG(R_X, R_A)); break;
        case BPF_MISC|BPF_TXA:
            emit(&b, BPF_MOV64_REG(R_A, R_X)); break;

        default:
            snprintf(errbuf, errlen, "unknown cBPF opcode 0x%02x at pc=%d", code, i);
            return -1;
        }
    }

    /* ---- end of cBPF: epilogue ---- */
    {
        /* natural fall-through from the cBPF program -> no match (R0 is 0
         * from the prologue XOR, unless the last ALU set it; for safety, set
         * R0=0).  VERIFIER: every insn must be reachable.  If the last cBPF
         * insn falls through (no RET, no jump), we reach here with possibly a
         * non-zero A.  For "no match" semantics write 0. */
        emit(&b, BPF_MOV32_IMM(R_A, 0));
    }

    /* ---- emit the shared epilogue (write R0→scratch; tail_call) ---- */
    int done_start = b.n;
    emit_epilogue(&b, scratch_fd, prog_array_fd);

    /* ---- fixup: resolve cbpf jump targets -> ebpf offsets ---- */
    for (i = 0; i < b.n_fixups; i++) {
        int idx = b.fixups[i].insn_idx;
        int tgt = b.fixups[i].target_cbpf_pc;
        if (tgt < 0 || tgt >= 512 || b.addrs[tgt] < 0) {
            snprintf(errbuf, errlen, "bad cBPF jump target %d", tgt); return -1;
        }
        b.insns[idx].off = b.addrs[tgt] - idx - 1;
    }

    /* ---- fixup: done JA's -> epilogue start ---- */
    for (i = 0; i < b.n_done; i++) {
        int idx = b.done_fixups[i];
        b.insns[idx].off = done_start - idx - 1;
    }

    if (b.n > INSNS) { snprintf(errbuf, errlen, "too many insns %d", b.n); return -1; }

    *out = malloc((size_t)b.n * sizeof(struct bpf_insn));
    if (!*out) { snprintf(errbuf, errlen, "OOM"); return -1; }
    memcpy(*out, b.insns, (size_t)b.n * sizeof(struct bpf_insn));
    *out_len = b.n;
    return 0;
}
