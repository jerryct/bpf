#include "bpf_entry.h"
#include "bpf_return.h"
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

  struct bpf_insn *const bpf_entry = (struct bpf_insn *)bpf_entry_text;
  const __u32 bpf_entry_len = bpf_entry_text_len / sizeof(struct bpf_insn);
  relocate_map_fd(bpf_entry, bpf_entry_len, 0x23, mfd);
  attach(bpf_entry, bpf_entry_len, "/sys/kernel/debug/tracing/events/uprobes/funclatency_entry/id");

  struct bpf_insn *const bpf_return = (struct bpf_insn *)bpf_return_text;
  const __u32 bpf_return_len = bpf_return_text_len / sizeof(struct bpf_insn);
  relocate_map_fd(bpf_return, bpf_return_len, 0x23, mfd);
  relocate_map_fd(bpf_return, bpf_return_len, 0x42, sfd);
  attach(bpf_return, bpf_return_len, "/sys/kernel/debug/tracing/events/uprobes/funclatency_return/id");

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
