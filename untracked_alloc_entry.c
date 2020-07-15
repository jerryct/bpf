#include <linux/bpf.h>
#include <linux/ptrace.h>
// order matters
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "memleak.h"

int bpf_prog(const struct pt_regs *const ctx) {
  (void)ctx;
  struct combined_alloc_info_t *existing_cinfo;
  struct combined_alloc_info_t cinfo = {0};

  __u64 pid = bpf_get_current_pid_tgid();
  existing_cinfo = bpf_map_lookup_elem((void *)0x23FFFFFFFF, &pid);
  if (existing_cinfo) {
    cinfo = *existing_cinfo;
  }
  cinfo.number_of_untracked_allocs += 1;
  bpf_map_update_elem((void *)0x23FFFFFFFF, &pid, &cinfo, BPF_ANY);

  return 0;
}
