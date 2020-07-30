// SPDX-License-Identifier: MIT

#include "stackcount.h"
#include "conditions.h"
#include "libbpf/bpf.h"
#include "loader.h"
#include "stackcount_entry.h"
#include "symbolizer.h"
#include <errno.h>
#include <limits.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static pid_t get_pid(const char *const buff) {
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
  ENSURES(argc > 2, "pid is missing");

  const pid_t pid = get_pid(argv[1]);
  const struct symbolizers *sym = create_symbolizers(&argv[2], argc - 2);

  set_rlimit();

  const int cfd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(struct key_t), sizeof(__u64), 256, 0);
  ENSURES(cfd >= 0, "cannot create map");
  const int sfd = bpf_create_map(BPF_MAP_TYPE_STACK_TRACE, sizeof(__u32), PERF_MAX_STACK_DEPTH * sizeof(__u64), 256, 0);
  ENSURES(sfd >= 0, "cannot create map");
  const int map[] = {cfd, sfd};
  const struct relocations relocs = {.fds = map, .size = sizeof(map) / sizeof(map[0])};

  const struct program prog = as_program(stackcount_entry, stackcount_entry_len);
  relocate_map_fd(prog, relocs);
  attach(prog, pid, "/sys/kernel/debug/tracing/events/uprobes/stackcount/id");

  while (1) {
    sleep(1);

    struct key_t key = {0};
    struct key_t next_key = {0};

    while (0 == bpf_map_get_next_key(cfd, &key, &next_key)) {
      __u64 count = 0;
      const int ret_count = bpf_map_lookup_elem(cfd, &next_key, &count);
      printf("\ncalled %llu times in %s [%u]\n", count, next_key.name, next_key.pid);
      if (ret_count == 0) {
        __u64 stack[PERF_MAX_STACK_DEPTH] = {0};
        const int ret_stack = bpf_map_lookup_elem(sfd, &next_key.user_stack_id, &stack);
        if (ret_stack == 0) {
          print_stack(sym, stack, sizeof(stack));
        }
      }
      key = next_key;
    };
  }

  return 0;
}
