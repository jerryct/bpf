#include <linux/bpf.h>
#include <linux/ptrace.h>
// order matters
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "memleak.h"

static inline void update_statistics_del(__u64 pid, const __u64 size) {
  struct combined_alloc_info_t *existing_cinfo;
  struct combined_alloc_info_t cinfo = {0};

  existing_cinfo = bpf_map_lookup_elem((void *)0x23FFFFFFFF, &pid);
  if (existing_cinfo) {
    cinfo = *existing_cinfo;
  }
  if (size >= cinfo.total_size) {
    cinfo.total_size = 0;
  } else {
    cinfo.total_size -= size;
  }
  if (cinfo.number_of_allocs > 0) {
    cinfo.number_of_allocs -= 1;
  }
  bpf_map_update_elem((void *)0x23FFFFFFFF, &pid, &cinfo, BPF_ANY);
}

int bpf_prog(const struct pt_regs *const ctx) {
  __u64 addr = PT_REGS_PARM1(ctx);
  struct alloc_info_t *info = bpf_map_lookup_elem((void *)0x72FFFFFFFF, &addr);
  if (!info) {
    return 0;
  }

  update_statistics_del(info->pid, info->size);
  bpf_map_delete_elem((void *)0x72FFFFFFFF, &addr);

  return 0;
}
