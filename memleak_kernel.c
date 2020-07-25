// SPDX-License-Identifier: MIT

#include <linux/bpf.h>
#include <linux/ptrace.h>
// order matters
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "memleak.h"

SEC(".malloc_entry")
int malloc_entry(const struct pt_regs *const ctx) {
  __u64 pid = bpf_get_current_pid_tgid();
  __u64 size = PT_REGS_PARM1(ctx);
  bpf_map_update_elem((void *)0xFFFFFF2300000001, &pid, &size, BPF_ANY);

  return 0;
}

static inline void update_statistics_add(__u64 pid, const __u64 size) {
  struct combined_alloc_info_t *existing_cinfo;
  struct combined_alloc_info_t cinfo = {0};

  existing_cinfo = bpf_map_lookup_elem((void *)0xFFFFFF2300000000, &pid);
  if (existing_cinfo) {
    cinfo = *existing_cinfo;
  }
  cinfo.total_size += size;
  cinfo.number_of_allocs += 1;
  bpf_map_update_elem((void *)0xFFFFFF2300000000, &pid, &cinfo, BPF_ANY);
}

SEC(".malloc_exit")
int malloc_exit(const struct pt_regs *const ctx) {
  __u64 pid = bpf_get_current_pid_tgid();
  __u64 *size = bpf_map_lookup_elem((void *)0xFFFFFF2300000001, &pid);
  struct alloc_info_t info = {0};
  if (!size) {
    return 0;
  }
  info.size = *size;
  bpf_map_delete_elem((void *)0xFFFFFF2300000001, &pid);
  info.timestamp_ns = bpf_ktime_get_ns();
  info.pid = pid; // change to bpf_get_stackid(ctx, stack_traces, BPF_F_USER_STACK);
  __u64 address = PT_REGS_RC(ctx);
  bpf_map_update_elem((void *)0xFFFFFF2300000002, &address, &info, BPF_ANY);
  update_statistics_add(info.pid, info.size);

  return 0;
}

static inline void update_statistics_del(__u64 pid, const __u64 size) {
  struct combined_alloc_info_t *existing_cinfo;
  struct combined_alloc_info_t cinfo = {0};

  existing_cinfo = bpf_map_lookup_elem((void *)0xFFFFFF2300000000, &pid);
  if (existing_cinfo) {
    cinfo = *existing_cinfo;
  }
  if (size >= cinfo.total_size) {
    cinfo.total_size = 0;
  } else {
    cinfo.total_size -= size;
  }
  if (cinfo.number_of_allocs > 0) {
    cinfo.number_of_allocs -= 1;
  }
  bpf_map_update_elem((void *)0xFFFFFF2300000000, &pid, &cinfo, BPF_ANY);
}

SEC(".free_entry")
int free_entry(const struct pt_regs *const ctx) {
  __u64 addr = PT_REGS_PARM1(ctx);
  struct alloc_info_t *info = bpf_map_lookup_elem((void *)0xFFFFFF2300000002, &addr);
  if (!info) {
    return 0;
  }

  update_statistics_del(info->pid, info->size);
  bpf_map_delete_elem((void *)0xFFFFFF2300000002, &addr);

  return 0;
}

SEC(".untracked_alloc_entry")
int untracked_alloc_entry(const struct pt_regs *const ctx) {
  (void)ctx;
  struct combined_alloc_info_t *existing_cinfo;
  struct combined_alloc_info_t cinfo = {0};

  __u64 pid = bpf_get_current_pid_tgid();
  existing_cinfo = bpf_map_lookup_elem((void *)0xFFFFFF2300000000, &pid);
  if (existing_cinfo) {
    cinfo = *existing_cinfo;
  }
  cinfo.number_of_untracked_allocs += 1;
  bpf_map_update_elem((void *)0xFFFFFF2300000000, &pid, &cinfo, BPF_ANY);

  return 0;
}
