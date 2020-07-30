// SPDX-License-Identifier: MIT

#ifndef STACKCOUNT_H
#define STACKCOUNT_H

#include <linux/types.h>

struct key_t {
  __u32 pid;
  int user_stack_id;
  char name[16]; // TASK_COMM_LEN
};

#endif // STACKCOUNT_H
