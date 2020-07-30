// SPDX-License-Identifier: MIT

#ifndef CONDITIONS_H
#define CONDITIONS_H

#include <errno.h>
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

#endif // CONDITIONS_H
