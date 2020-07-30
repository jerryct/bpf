// SPDX-License-Identifier: MIT

#include "symbolizer.h"
#include "conditions.h"
#include "loader.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static pid_t start_subprocess(const char *const program, const char *const argv[], const char *const envp[],
                              const int stdin_fd, const int stdout_fd, const int stderr_fd) {
  const int kInvalidFd = -1;

  const int pid = fork();
  if (pid < 0) {
    return pid;
  }

  if (pid == 0) { // child process
    if (stdin_fd != kInvalidFd) {
      close(STDIN_FILENO);
      dup2(stdin_fd, STDIN_FILENO);
      close(stdin_fd);
    }
    if (stdout_fd != kInvalidFd) {
      close(STDOUT_FILENO);
      dup2(stdout_fd, STDOUT_FILENO);
      close(stdout_fd);
    }
    if (stderr_fd != kInvalidFd) {
      close(STDERR_FILENO);
      dup2(stderr_fd, STDERR_FILENO);
      close(stderr_fd);
    }

    for (int fd = (int)sysconf(_SC_OPEN_MAX); fd > 2; fd--) {
      close(fd);
    }

    execve(program, (char *const *)&argv[0], (char *const *)envp);
    exit(1);
  }

  return pid;
}

static int create_two_high_numbered_pipes(int *const input_fd, int *const output_fd) {
  int *in_fd = NULL;
  int *out_fd = NULL;
  // The client program may close its stdin and/or stdout and/or stderr thus allowing socketpair to reuse file
  // descriptors 0, 1 or 2. In this case the communication between the forked processes may be broken if either the
  // parent or the child tries to close or duplicate these descriptors. The loop below produces two pairs of file
  // descriptors, each greater than 2 (stderr).
  int sock_pair[5][2];
  for (int i = 0; i < 5; ++i) {
    if (pipe(sock_pair[i]) == -1) {
      for (int j = 0; j < i; ++j) {
        close(sock_pair[j][0]);
        close(sock_pair[j][1]);
      }
      return 0;
    } else if ((sock_pair[i][0] > 2) && (sock_pair[i][1] > 2)) {
      if (in_fd == NULL) {
        in_fd = sock_pair[i];
      } else {
        out_fd = sock_pair[i];
        for (int j = 0; j < i; ++j) {
          if (sock_pair[j] == in_fd) {
            continue;
          }
          close(sock_pair[j][0]);
          close(sock_pair[j][1]);
        }
        break;
      }
    }
  }
  ENSURES(in_fd != NULL, "cannot create input fd for socket pair");
  ENSURES(out_fd != NULL, "cannot create output fd for socket pair");
  input_fd[0] = in_fd[0];
  input_fd[1] = in_fd[1];
  output_fd[0] = out_fd[0];
  output_fd[1] = out_fd[1];
  return 1;
}

static void is_process_running(const pid_t pid) {
  int process_status;
  const pid_t waitpid_status = waitpid(pid, &process_status, WNOHANG);
  ENSURES(waitpid_status == 0, "waiting on the process failed");
}

static pid_t start_symbolizer(const char *const pathname, int *const input_fd, int *const output_fd) {
  const char *argv[4];
  argv[0] = "/usr/bin/addr2line";
  argv[1] = "-ipCfe";
  argv[2] = pathname;
  argv[3] = NULL;

  int in_fd[2] = {0};
  int out_fd[2] = {0};
  const int ret = create_two_high_numbered_pipes(in_fd, out_fd);
  ENSURES(ret != 0, "can't create a socket pair to start external symbolizer");

  const pid_t pid = start_subprocess(argv[0], argv, NULL, out_fd[0], in_fd[1], -1);
  if (pid < 0) {
    close(in_fd[0]);
    close(out_fd[1]);
    return pid;
  }

  *input_fd = in_fd[0];
  *output_fd = out_fd[1];

  return pid;
}

struct memory_map {
  const char *pathname;
  __u64 start;
  __u64 end;
  pid_t pid;
  int input_fd;
  int output_fd;
};

struct symbolizers {
  struct memory_map *mmap;
  int len;
};

static void symbolize(const struct symbolizers *const symbolizers, const __u64 address, char *const symbol,
                      const int len) {
  const struct memory_map *it = NULL;
  for (int i = 0; i < symbolizers->len; ++i) {
    if ((symbolizers->mmap[i].start <= address) && (address < symbolizers->mmap[i].end)) {
      it = &symbolizers->mmap[i];
      break;
    }
  }

  if (!it) {
    symbol[0] = '?';
    symbol[1] = '\n';
    symbol[2] = '\0';
    return;
  }

  char buffer[18] = {0}; // 16 digits for __u64 + 1 newline + 1 null termination for strlen
  snprintf(buffer, sizeof(buffer), "%llx\n", address - it->start);
  const ssize_t ret_write = write(it->output_fd, buffer, strlen(buffer));
  ENSURES(ret_write >= 0, "cannot request symbols");

  ENSURES(len > 0, "symbol buffer length must be greater than 0");
  const ssize_t ret_read = read(it->input_fd, symbol, (size_t)len);
  ENSURES(ret_read >= 0, "cannot read symbols");
  ENSURES(ret_read != len, "symbol buffer too small");
  symbol[ret_read] = '\0';
}

void print_stack(const struct symbolizers *const symbolizers, const __u64 *const stack, const int stack_len) {
  ENSURES(symbolizers != NULL, "symbolizers must not be NULL");
  ENSURES(stack_len >= 0, "stack length must be greater than 0");
  for (int i = 0; i < stack_len; ++i) {
    if (stack[i] == 0) {
      break;
    }

    char symbol[1024];
    symbolize(symbolizers, stack[i], symbol, sizeof(symbol));
    printf("    #%d 0x%llx in %s", i, stack[i], symbol);
  }
}

static __u64 get_address(const char *const buff) {
  char *end;
  errno = 0;

  const __u64 address = strtoull(buff, &end, 16);

  ENSURES(end != buff, "not a decimal number");
  ENSURES('\0' == *end, "extra characters at end of input");
  ENSURES((ULLONG_MAX != address) && (ERANGE != errno), "out of range of type long long");

  return address;
}

struct symbolizers *create_symbolizers(char *const mmap[], const int len) {
  ENSURES(mmap != NULL, "mmap must not be NULL");
  ENSURES(len >= 0, "mmap length must be greater than 0");
  ENSURES((len % 3) == 0, "mmap triple must be 'pathname address_start address_end'");

  struct symbolizers *sym = malloc(sizeof(struct symbolizers));
  ENSURES(sym != NULL, "malloc failed");
  sym->len = len / 3;
  sym->mmap = malloc((size_t)sym->len * sizeof(struct memory_map));
  ENSURES(sym->mmap != NULL, "malloc failed");

  struct memory_map *it = sym->mmap;
  for (int i = 0; i < len; i += 3) {
    it->pathname = mmap[i];
    it->start = get_address(mmap[i + 1]);
    it->end = get_address(mmap[i + 2]);
    it->pid = start_symbolizer(it->pathname, &it->input_fd, &it->output_fd);
    ENSURES(it->pid > 0, "failed to start symbolizer");
    ++it;
  }

  sleep(1);

  for (int i = 0; i < sym->len; ++i) {
    it = &sym->mmap[i];
    is_process_running(it->pid);
    printf("created symbolizer for %s: 0x%llx-0x%llx\n", it->pathname, it->start, it->end);
  }

  return sym;
}
