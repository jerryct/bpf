// SPDX-License-Identifier: MIT

#include <linux/types.h>

// combined_allocs := 23
// sizes := 42
// allocs := 72

struct alloc_info_t {
  __u64 size;
  __u64 timestamp_ns;
  __u64 pid; // should be int stack_id
};
struct combined_alloc_info_t {
  __u64 total_size;
  __u64 number_of_allocs;
  __u64 number_of_untracked_allocs;
};
