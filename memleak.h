// SPDX-License-Identifier: MIT

#ifndef MEMLEAK_H
#define MEMLEAK_H

#include <linux/types.h>

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

#endif // MEMLEAK_H
