// SPDX-License-Identifier: MIT

#include <linux/bpf.h>
// order matters
#include "bpf_helpers.h"
#include "stackcount.h"

SEC(".stackcount_entry")
int stackcount_entry(void *const ctx) {
  struct key_t key = {0};
  key.pid = bpf_get_current_pid_tgid() & 0xFFFF;
  key.user_stack_id = bpf_get_stackid(ctx, (void *)0xFFFFFF2300000001, BPF_F_USER_STACK);
  bpf_get_current_comm(&key.name, sizeof(key.name));

  __u64 *const count = bpf_map_lookup_elem((void *)0xFFFFFF2300000000, &key);
  if (count) {
    ++(*count);
  } else {
    __u64 initial = 1;
    bpf_map_update_elem((void *)0xFFFFFF2300000000, &key, &initial, BPF_ANY);
  }
  return 0;
}
