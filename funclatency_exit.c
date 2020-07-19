// SPDX-License-Identifier: MIT

#include <linux/bpf.h>
// order matters
#include "bpf_helpers.h"

int bpf_prog(void *ctx) {
  (void)ctx;
  const __u64 now = bpf_ktime_get_ns();
  __u32 tid = bpf_get_current_pid_tgid() & 0xFFFF;

  const __u64 *const value = bpf_map_lookup_elem((void *)0x23FFFFFFFF, &tid);
  if (value) {
    __u32 i = 0;
    __u64 *const sum = bpf_map_lookup_elem((void *)0x42FFFFFFFF, &i);
    if (sum) {
      const __u64 delta = now - *value;
      __sync_fetch_and_add(sum, delta / 1000);
      bpf_map_delete_elem((void *)0x23FFFFFFFF, &tid);
    }
    __u32 j = 1;
    __u64 *const count = bpf_map_lookup_elem((void *)0x42FFFFFFFF, &j);
    if (count) {
      __sync_fetch_and_add(count, 1);
    }
  }

  return 0;
}
