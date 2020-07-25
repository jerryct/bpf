// SPDX-License-Identifier: MIT

#include "funclatency_entry.h"
#include "funclatency_exit.h"
#include "libbpf/bpf.h"
#include "loader.h"
#include <linux/bpf.h>
#include <linux/types.h>
#include <stdio.h>
#include <unistd.h>

static __u64 at(const int fd, const __u32 key) {
  __u64 value = 0;
  const int r = bpf_map_lookup_elem(fd, &key, &value);
  ENSURES(r == 0, "out-of-bounds");
  return value;
}

int main(void) {
  set_rlimit();

  const int mfd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u32), sizeof(__u64), 256, 0);
  const int sfd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(__u32), sizeof(__u64), 2, 0);
  const int map[] = {mfd, sfd};
  const struct relocations relocs = {.fds = map, .size = sizeof(map) / sizeof(map[0])};

  struct bpf_insn *const funclatency_entry_prog = (struct bpf_insn *)funclatency_entry;
  const __u32 funclatency_entry_prog_len = funclatency_entry_len / sizeof(struct bpf_insn);
  relocate_map_fd(funclatency_entry_prog, funclatency_entry_prog_len, relocs);
  attach(funclatency_entry_prog, funclatency_entry_prog_len, -1,
         "/sys/kernel/debug/tracing/events/uprobes/funclatency_entry/id");

  struct bpf_insn *const funclatency_prog_exit = (struct bpf_insn *)funclatency_exit;
  const __u32 funclatency_exit_prog_len = funclatency_exit_len / sizeof(struct bpf_insn);
  relocate_map_fd(funclatency_prog_exit, funclatency_exit_prog_len, relocs);
  attach(funclatency_prog_exit, funclatency_exit_prog_len, -1,
         "/sys/kernel/debug/tracing/events/uprobes/funclatency_return/id");

  while (1) {
    sleep(1);

    const __u64 sum = at(sfd, 0);
    const __u64 count = at(sfd, 1);
    if (count > 0) {
      printf("mean: %llu [us] - count: %llu\n", sum / count, count);
    }
  }

  return 0;
}
