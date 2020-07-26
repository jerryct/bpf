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
      printf("loader [%s:%d (%s)] %s - errno: %s\n", __FILE__, __LINE__, __func__, s, strerror(errno));                \
      exit(EXIT_FAILURE);                                                                                              \
    }                                                                                                                  \
  } while (0)

struct relocations {
  const int *fds;
  int size;
};

struct program {
  struct bpf_insn *insn;
  int len;
};

struct program as_program(unsigned char *const insn, const unsigned len);
void relocate_map_fd(const struct program prog, const struct relocations relocs);
void attach(const struct program prog, const pid_t pid, const char *const probe);
void set_rlimit();

#endif // LOADER_H
