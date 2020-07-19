// SPDX-License-Identifier: MIT

#ifndef LOADER_H
#define LOADER_H

#include <errno.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ENSURES(c, s)                                                                                                  \
  do {                                                                                                                 \
    const int condition = c;                                                                                           \
    if (!condition) {                                                                                                  \
      printf("loader [%s:%d (%s)] %s: %s\n", __FILE__, __LINE__, __func__, s, strerror(errno));                        \
      exit(EXIT_FAILURE);                                                                                              \
    }                                                                                                                  \
  } while (0)

void relocate_map_fd(struct bpf_insn *const insn, const int n, const int p, const int fd);
void attach(const struct bpf_insn *const prog, const __u32 len, const pid_t pid, const char *const probe);
void set_rlimit();

#endif // LOADER_H
