// SPDX-License-Identifier: MIT

#include "memleak.h"
#include "free_entry.h"
#include "libbpf/bpf.h"
#include "loader.h"
#include "malloc_entry.h"
#include "malloc_exit.h"
#include "untracked_alloc_entry.h"
#include <limits.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <stdio.h>
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

  struct bpf_insn *const malloc_entry_prog = (struct bpf_insn *)malloc_entry;
  const __u32 malloc_entry_prog_len = malloc_entry_len / sizeof(struct bpf_insn);
  relocate_map_fd(malloc_entry_prog, malloc_entry_prog_len, 0x23, ca_fd);
  relocate_map_fd(malloc_entry_prog, malloc_entry_prog_len, 0x42, s_fd);
  relocate_map_fd(malloc_entry_prog, malloc_entry_prog_len, 0x72, a_fd);
  attach(malloc_entry_prog, malloc_entry_prog_len, pid, "/sys/kernel/debug/tracing/events/uprobes/malloc_entry/id");

  struct bpf_insn *const malloc_exit_prog = (struct bpf_insn *)malloc_exit;
  const __u32 malloc_exit_prog_len = malloc_exit_len / sizeof(struct bpf_insn);
  relocate_map_fd(malloc_exit_prog, malloc_exit_prog_len, 0x23, ca_fd);
  relocate_map_fd(malloc_exit_prog, malloc_exit_prog_len, 0x42, s_fd);
  relocate_map_fd(malloc_exit_prog, malloc_exit_prog_len, 0x72, a_fd);
  attach(malloc_exit_prog, malloc_exit_prog_len, pid, "/sys/kernel/debug/tracing/events/uprobes/malloc_exit/id");

  struct bpf_insn *const free_entry_prog = (struct bpf_insn *)free_entry;
  const __u32 free_entry_prog_len = free_entry_len / sizeof(struct bpf_insn);
  relocate_map_fd(free_entry_prog, free_entry_prog_len, 0x23, ca_fd);
  relocate_map_fd(free_entry_prog, free_entry_prog_len, 0x42, s_fd);
  relocate_map_fd(free_entry_prog, free_entry_prog_len, 0x72, a_fd);
  attach(free_entry_prog, free_entry_prog_len, pid, "/sys/kernel/debug/tracing/events/uprobes/free_entry/id");

  struct bpf_insn *const untracked_alloc_prog = (struct bpf_insn *)untracked_alloc_entry;
  const __u32 untracked_alloc_prog_len = untracked_alloc_entry_len / sizeof(struct bpf_insn);
  relocate_map_fd(untracked_alloc_prog, untracked_alloc_prog_len, 0x23, ca_fd);
  attach(untracked_alloc_prog, untracked_alloc_prog_len, pid,
         "/sys/kernel/debug/tracing/events/uprobes/calloc_entry/id");
  attach(untracked_alloc_prog, untracked_alloc_prog_len, pid,
         "/sys/kernel/debug/tracing/events/uprobes/realloc_entry/id");
  attach(untracked_alloc_prog, untracked_alloc_prog_len, pid,
         "/sys/kernel/debug/tracing/events/uprobes/posix_memalign_entry/id");
  attach(untracked_alloc_prog, untracked_alloc_prog_len, pid,
         "/sys/kernel/debug/tracing/events/uprobes/aligned_alloc_entry/id");

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
