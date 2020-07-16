#include "loader.h"
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

void relocate_map_fd(struct bpf_insn *const insn, const int n, const int p, const int fd) {
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

void attach(const struct bpf_insn *const prog, const __u32 len, const char *const probe) {
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

void set_rlimit() {
  const struct rlimit lim = {.rlim_cur = RLIM_INFINITY, .rlim_max = RLIM_INFINITY};
  const int ret_rlimit = setrlimit(RLIMIT_MEMLOCK, &lim);
  ENSURES(ret_rlimit == 0, "cannot set rlimit");
}
