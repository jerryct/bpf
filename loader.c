#include "bpf_entry.h"
#include "bpf_return.h"
#include "libbpf/bpf.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <linux/version.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define ENSURES(c, s)                                                                                                  \
  do {                                                                                                                 \
    const int condition = c;                                                                                           \
    if (!condition) {                                                                                                  \
      printf("loader [%s:%d (%s)] %s: %s\n", __FILE__, __LINE__, __func__, s, strerror(errno));                        \
      exit(EXIT_FAILURE);                                                                                              \
    }                                                                                                                  \
  } while (0)

static void relocate_map_fd(struct bpf_insn *const insn, const int n, const int p, const int fd) {
  for (int i = 0; i < n; ++i) {
    if ((insn[i].code == BPF_DW) && (insn[i + 1].imm == p)) {
      printf("insn[%d]: %x %x %x %x %x", i, insn[i].code, insn[i].dst_reg, insn[i].src_reg, insn[i].off, insn[i].imm);
      insn[i].src_reg = BPF_PSEUDO_MAP_FD;
      insn[i].imm = fd;
      insn[i + 1].imm = 0;
      printf(" -> %x %x %x %x %x\n", insn[i].code, insn[i].dst_reg, insn[i].src_reg, insn[i].off, insn[i].imm);
    }
  }
}

static __u64 read_probe_id(const char *s) {
  const int fd = open(s, O_RDONLY, 0);
  ENSURES(fd >= 0, "cannot open probe id");
  char buf[21] = {0};
  const ssize_t n = read(fd, buf, sizeof(buf));
  close(fd);
  ENSURES(n >= 0, "cannot read probe id");
  buf[n] = '\0';
  const __u64 id = strtoull(buf, NULL, 10);
  ENSURES(errno == 0, "cannot convert probe id");
  return id;
}

static void attach(const struct bpf_insn *const prog, const __u32 len, const char *const probe) {
  char log[BPF_LOG_BUF_SIZE] = {0};
  const int pfd = bpf_load_program(BPF_PROG_TYPE_KPROBE, prog, len, "GPL", LINUX_VERSION_CODE, log, sizeof(log));
  if (pfd < 0) {
    printf("cannot load BPF program: %s\n", strerror(errno));
    printf(">>>>\n%s<<<<\n", log);
    exit(EXIT_FAILURE);
  }

  struct perf_event_attr pattr = {0};
  pattr.type = PERF_TYPE_TRACEPOINT;
  pattr.sample_type = PERF_SAMPLE_RAW;
  pattr.sample_period = 1;
  pattr.wakeup_events = 1;
  pattr.config = read_probe_id(probe);
  pattr.size = sizeof(pattr);
  const int efd = syscall(SYS_perf_event_open, &pattr, -1, 0, -1, 0);
  ENSURES(efd >= 0, "cannot open event");
  const int ret_enable = ioctl(efd, PERF_EVENT_IOC_ENABLE, 0);
  ENSURES(ret_enable >= 0, "cannot enable event");
  const int ret_attach = ioctl(efd, PERF_EVENT_IOC_SET_BPF, pfd);
  ENSURES(ret_attach >= 0, "cannot attach BPF program to event");
}

static __u64 at(const int fd, const __u32 key) {
  __u64 value = 0;
  const int r = bpf_map_lookup_elem(fd, &key, &value);
  ENSURES(r == 0, "out-of-bounds");
  return value;
}

int main(void) {
  const struct rlimit lim = {.rlim_cur = RLIM_INFINITY, .rlim_max = RLIM_INFINITY};
  const int ret_rlimit = setrlimit(RLIMIT_MEMLOCK, &lim);
  ENSURES(ret_rlimit == 0, "cannot set rlimit");

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
