#/usr/bin/env sh
#
# Trace and display outstanding allocations to detect
# memory leaks in user-mode processes.
#
# tracked: malloc
# untracked: calloc, realloc, posix_memalign, aligned_alloc
# obsolete: valloc, memalign, pvalloc

set -eu

script_root="$(cd "$(dirname "$0")" && pwd)"

echo > /sys/kernel/debug/tracing/uprobe_events
perf probe -x /lib/x86_64-linux-gnu/libc.so.6 'uprobes:malloc_entry=malloc'
perf probe -x /lib/x86_64-linux-gnu/libc.so.6 'uprobes:malloc_exit=malloc%return'
perf probe -x /lib/x86_64-linux-gnu/libc.so.6 'uprobes:free_entry=free'
perf probe -x /lib/x86_64-linux-gnu/libc.so.6 'uprobes:calloc_entry=calloc'
perf probe -x /lib/x86_64-linux-gnu/libc.so.6 'uprobes:realloc_entry=realloc'
perf probe -x /lib/x86_64-linux-gnu/libc.so.6 'uprobes:posix_memalign_entry=posix_memalign'
perf probe -x /lib/x86_64-linux-gnu/libc.so.6 'uprobes:aligned_alloc_entry=aligned_alloc'
cat /sys/kernel/debug/tracing/uprobe_events

exec "$script_root/memleak" $1
