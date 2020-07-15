// SPDX-License-Identifier: MIT

#include <linux/bpf.h>
#include <linux/ptrace.h>
// order matters
#include "bpf_helpers.h"
#include "bpf_tracing.h"

int bpf_prog(const struct pt_regs *const ctx) {
  __u64 pid = bpf_get_current_pid_tgid();
  __u64 size = PT_REGS_PARM1(ctx);
  bpf_map_update_elem((void *)0x42FFFFFFFF, &pid, &size, BPF_ANY);

  return 0;
}
