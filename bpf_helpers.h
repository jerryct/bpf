/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H

/* helper macro to place programs, maps, license in
 * different sections in elf_bpf file. Section names
 * are interpreted by elf_bpf loader
 */
#define SEC(NAME) __attribute__((section(NAME), used))

/* helper functions called from eBPF programs written in C */
static void *(*bpf_map_lookup_elem)(void *map, void *key) = (void *)BPF_FUNC_map_lookup_elem;
static int (*bpf_map_update_elem)(void *map, void *key, void *value,
                                  unsigned long long flags) = (void *)BPF_FUNC_map_update_elem;
static int (*bpf_map_delete_elem)(void *map, void *key) = (void *)BPF_FUNC_map_delete_elem;
static int (*bpf_probe_read)(void *dst, int size, void *unsafe_ptr) = (void *)BPF_FUNC_probe_read;
static unsigned long long (*bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;
static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) = (void *)BPF_FUNC_trace_printk;
static void (*bpf_tail_call)(void *ctx, void *map, int index) = (void *)BPF_FUNC_tail_call;
static unsigned long long (*bpf_get_smp_processor_id)(void) = (void *)BPF_FUNC_get_smp_processor_id;
static unsigned long long (*bpf_get_current_pid_tgid)(void) = (void *)BPF_FUNC_get_current_pid_tgid;
static unsigned long long (*bpf_get_current_uid_gid)(void) = (void *)BPF_FUNC_get_current_uid_gid;
static int (*bpf_get_current_comm)(void *buf, int buf_size) = (void *)BPF_FUNC_get_current_comm;
static unsigned long long (*bpf_perf_event_read)(void *map,
                                                 unsigned long long flags) = (void *)BPF_FUNC_perf_event_read;
static int (*bpf_clone_redirect)(void *ctx, int ifindex, int flags) = (void *)BPF_FUNC_clone_redirect;
static int (*bpf_redirect)(int ifindex, int flags) = (void *)BPF_FUNC_redirect;
static int (*bpf_redirect_map)(void *map, int key, int flags) = (void *)BPF_FUNC_redirect_map;
static int (*bpf_perf_event_output)(void *ctx, void *map, unsigned long long flags, void *data,
                                    int size) = (void *)BPF_FUNC_perf_event_output;
static int (*bpf_get_stackid)(void *ctx, void *map, int flags) = (void *)BPF_FUNC_get_stackid;
static int (*bpf_probe_write_user)(void *dst, void *src, int size) = (void *)BPF_FUNC_probe_write_user;
static int (*bpf_current_task_under_cgroup)(void *map, int index) = (void *)BPF_FUNC_current_task_under_cgroup;
static int (*bpf_skb_get_tunnel_key)(void *ctx, void *key, int size, int flags) = (void *)BPF_FUNC_skb_get_tunnel_key;
static int (*bpf_skb_set_tunnel_key)(void *ctx, void *key, int size, int flags) = (void *)BPF_FUNC_skb_set_tunnel_key;
static int (*bpf_skb_get_tunnel_opt)(void *ctx, void *md, int size) = (void *)BPF_FUNC_skb_get_tunnel_opt;
static int (*bpf_skb_set_tunnel_opt)(void *ctx, void *md, int size) = (void *)BPF_FUNC_skb_set_tunnel_opt;
static unsigned long long (*bpf_get_prandom_u32)(void) = (void *)BPF_FUNC_get_prandom_u32;
static int (*bpf_xdp_adjust_head)(void *ctx, int offset) = (void *)BPF_FUNC_xdp_adjust_head;
static int (*bpf_xdp_adjust_meta)(void *ctx, int offset) = (void *)BPF_FUNC_xdp_adjust_meta;
static int (*bpf_setsockopt)(void *ctx, int level, int optname, void *optval, int optlen) = (void *)BPF_FUNC_setsockopt;
static int (*bpf_getsockopt)(void *ctx, int level, int optname, void *optval, int optlen) = (void *)BPF_FUNC_getsockopt;
static int (*bpf_sk_redirect_map)(void *ctx, void *map, int key, int flags) = (void *)BPF_FUNC_sk_redirect_map;
static int (*bpf_sock_map_update)(void *map, void *key, void *value,
                                  unsigned long long flags) = (void *)BPF_FUNC_sock_map_update;
static int (*bpf_perf_event_read_value)(void *map, unsigned long long flags, void *buf,
                                        unsigned int buf_size) = (void *)BPF_FUNC_perf_event_read_value;
static int (*bpf_perf_prog_read_value)(void *ctx, void *buf,
                                       unsigned int buf_size) = (void *)BPF_FUNC_perf_prog_read_value;

/* llvm builtin functions that eBPF C program may use to
 * emit BPF_LD_ABS and BPF_LD_IND instructions
 */
struct sk_buff;
unsigned long long load_byte(void *skb, unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb, unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb, unsigned long long off) asm("llvm.bpf.load.word");

/* a helper structure used by eBPF C program
 * to describe map attributes to elf_bpf loader
 */
struct bpf_map_def {
  unsigned int type;
  unsigned int key_size;
  unsigned int value_size;
  unsigned int max_entries;
  unsigned int map_flags;
  unsigned int inner_map_idx;
  unsigned int numa_node;
};

static int (*bpf_skb_load_bytes)(void *ctx, int off, void *to, int len) = (void *)BPF_FUNC_skb_load_bytes;
static int (*bpf_skb_store_bytes)(void *ctx, int off, void *from, int len,
                                  int flags) = (void *)BPF_FUNC_skb_store_bytes;
static int (*bpf_l3_csum_replace)(void *ctx, int off, int from, int to, int flags) = (void *)BPF_FUNC_l3_csum_replace;
static int (*bpf_l4_csum_replace)(void *ctx, int off, int from, int to, int flags) = (void *)BPF_FUNC_l4_csum_replace;
static int (*bpf_skb_under_cgroup)(void *ctx, void *map, int index) = (void *)BPF_FUNC_skb_under_cgroup;
static int (*bpf_skb_change_head)(void *, int len, int flags) = (void *)BPF_FUNC_skb_change_head;

#endif
