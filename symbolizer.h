// SPDX-License-Identifier: MIT

#ifndef SYMBOLIZER_H
#define SYMBOLIZER_H

#include <linux/types.h>

struct symbolizers;

struct symbolizers *create_symbolizers(char *const mmap[], const int len);
void print_stack(const struct symbolizers *const symbolizers, const __u64 *const stack, const int stack_len);

#endif // SYMBOLIZER_H
