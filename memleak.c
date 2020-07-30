// SPDX-License-Identifier: MIT

#include "memleak.h"
#include "conditions.h"
#include "free_entry.h"
#include "libbpf/bpf.h"
#include "loader.h"
#include "malloc_entry.h"
#include "malloc_exit.h"
#include "untracked_alloc_entry.h"
#include <errno.h>
#include <limits.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static inline pid_t GetPid(const char *const buff) {
  char *end;
  errno = 0;

  const long pid = strtol(buff, &end, 10);

  ENSURES(end != buff, "not a decimal number");
  ENSURES('\0' == *end, "extra characters at end of input");
  ENSURES((LONG_MIN != pid || LONG_MAX != pid) && ERANGE != errno, "out of range of type long");
  ENSURES(pid <= INT_MAX, "greater than INT_MAX");
  ENSURES(pid >= INT_MIN, "less than INT_MIN");

  return (pid_t)pid;
}

int main(const int argc, char *argv[]) {
  ENSURES(argc == 2, "pid is missing");

  const pid_t pid = GetPid(argv[1]);

  set_rlimit();

  const int ca_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u64), sizeof(struct combined_alloc_info_t), 10240, 0);
  const int s_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u64), sizeof(__u64), 1000, 0);
  const int a_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u64), sizeof(struct alloc_info_t), 1000000, 0);
  const int map[] = {ca_fd, s_fd, a_fd};
  const struct relocations relocs = {.fds = map, .size = sizeof(map) / sizeof(map[0])};

  const struct program malloc_entry_prog = as_program(malloc_entry, malloc_entry_len);
  relocate_map_fd(malloc_entry_prog, relocs);
  attach(malloc_entry_prog, pid, "/sys/kernel/debug/tracing/events/uprobes/malloc_entry/id");

  const struct program malloc_exit_prog = as_program(malloc_exit, malloc_exit_len);
  relocate_map_fd(malloc_exit_prog, relocs);
  attach(malloc_exit_prog, pid, "/sys/kernel/debug/tracing/events/uprobes/malloc_exit/id");

  const struct program free_entry_prog = as_program(free_entry, free_entry_len);
  relocate_map_fd(free_entry_prog, relocs);
  attach(free_entry_prog, pid, "/sys/kernel/debug/tracing/events/uprobes/free_entry/id");

  const struct program untracked_alloc_prog = as_program(untracked_alloc_entry, untracked_alloc_entry_len);
  relocate_map_fd(untracked_alloc_prog, relocs);
  attach(untracked_alloc_prog, pid, "/sys/kernel/debug/tracing/events/uprobes/calloc_entry/id");
  attach(untracked_alloc_prog, pid, "/sys/kernel/debug/tracing/events/uprobes/realloc_entry/id");
  attach(untracked_alloc_prog, pid, "/sys/kernel/debug/tracing/events/uprobes/posix_memalign_entry/id");
  attach(untracked_alloc_prog, pid, "/sys/kernel/debug/tracing/events/uprobes/aligned_alloc_entry/id");

  while (1) {
    sleep(1);

    __u64 key = 0;
    __u64 next_key = 0;

    while (0 == bpf_map_get_next_key(ca_fd, &key, &next_key)) {
      struct combined_alloc_info_t value = {0};
      const int r = bpf_map_lookup_elem(ca_fd, &next_key, &value);
      if (r == 0) {
        const __u32 pid = next_key >> 32;
        const __u32 tid = next_key & 0xFFFF;
        printf("pid: %u, tid: %u – size: %llu [bytes] - count: %llu - untracked: %llu\n", pid, tid, value.total_size,
               value.number_of_allocs, value.number_of_untracked_allocs);
      }
      key = next_key;
    };
  }

  return 0;
}
