// SPDX-License-Identifier: MIT

#include <linux/bpf.h>
#include <linux/ptrace.h>
// order matters
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "memleak.h"

static inline void update_statistics_add(__u64 pid, const __u64 size) {
  struct combined_alloc_info_t *existing_cinfo;
  struct combined_alloc_info_t cinfo = {0};

  existing_cinfo = bpf_map_lookup_elem((void *)0x23FFFFFFFF, &pid);
  if (existing_cinfo) {
    cinfo = *existing_cinfo;
  }
  cinfo.total_size += size;
  cinfo.number_of_allocs += 1;
  bpf_map_update_elem((void *)0x23FFFFFFFF, &pid, &cinfo, BPF_ANY);
}

int bpf_prog(const struct pt_regs *const ctx) {
  __u64 pid = bpf_get_current_pid_tgid();
  __u64 *size = bpf_map_lookup_elem((void *)0x42FFFFFFFF, &pid);
  struct alloc_info_t info = {0};
  if (!size) {
    return 0;
  }
  info.size = *size;
  bpf_map_delete_elem((void *)0x42FFFFFFFF, &pid);
  info.timestamp_ns = bpf_ktime_get_ns();
  info.pid = pid; // change to bpf_get_stackid(ctx, stack_traces, BPF_F_USER_STACK);
  __u64 address = PT_REGS_RC(ctx);
  bpf_map_update_elem((void *)0x72FFFFFFFF, &address, &info, BPF_ANY);
  update_statistics_add(info.pid, info.size);

  return 0;
}
