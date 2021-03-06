// SPDX-License-Identifier: MIT

#include <linux/bpf.h>
// order matters
#include "bpf_helpers.h"

SEC(".funclatency_entry")
int funclatency_entry(void *ctx) {
  (void)ctx;
  __u64 now = bpf_ktime_get_ns();
  __u32 tid = bpf_get_current_pid_tgid() & 0xFFFF;
  bpf_map_update_elem((void *)0xFFFFFF2300000000, &tid, &now, BPF_ANY);

  return 0;
}

SEC(".funclatency_exit")
int funclatency_exit(void *ctx) {
  (void)ctx;
  const __u64 now = bpf_ktime_get_ns();
  __u32 tid = bpf_get_current_pid_tgid() & 0xFFFF;

  const __u64 *const value = bpf_map_lookup_elem((void *)0xFFFFFF2300000000, &tid);
  if (value) {
    __u32 i = 0;
    __u64 *const sum = bpf_map_lookup_elem((void *)0xFFFFFF2300000001, &i);
    if (sum) {
      const __u64 delta = now - *value;
      __sync_fetch_and_add(sum, delta / 1000);
      bpf_map_delete_elem((void *)0xFFFFFF2300000000, &tid);
    }
    __u32 j = 1;
    __u64 *const count = bpf_map_lookup_elem((void *)0xFFFFFF2300000001, &j);
    if (count) {
      __sync_fetch_and_add(count, 1);
    }
  }

  return 0;
}
