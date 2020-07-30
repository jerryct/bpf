// SPDX-License-Identifier: MIT

#ifndef LOADER_H
#define LOADER_H

#include <linux/bpf.h>
#include <sys/types.h>

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
