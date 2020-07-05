#include <linux/bpf.h>
// order matters
#include "bpf_helpers.h"

int bpf_prog(void *ctx) {
  (void)ctx;
  __u64 now = bpf_ktime_get_ns();
  __u32 tid = bpf_get_current_pid_tgid() & 0xFFFF;
  bpf_map_update_elem((void *)0x23FFFFFFFF, &tid, &now, BPF_ANY);

  return 0;
}
