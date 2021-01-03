# BPF

[BCC](https://github.com/iovisor/bcc) and [bpftrace](https://github.com/iovisor/bpftrace) need
parts of the LLVM infrastructure to run on the target system. Especially on embedded systems
one may need a minimal set of dependencies to constraint resources. Although the project
[ply](https://github.com/iovisor/ply) exists, which has the same goal, this project teached
me the internals of BPF.

The BPF kernel is compiled on the host with the LLVM toolchain. `xxd` converts the resulting
BPF object into a header file which is embedded in the final binary for the target system.

## Prequisites

Ubuntu 18.04 LTS

```
sudo apt install --no-install-recommends ninja-build xxd clang-10 llvm-10
```

## Build

```
ninja
```

## Examples

```
$ cat function.c
#include <unistd.h>

int __attribute__ ((noinline)) Foo(int x) {
  sleep(1);
  return x;
}

int Bar(int x){ Foo(x); }

int main(void) {
  int i = 0;
  while (1) {
    Bar(i++);
  }
  return 0;
}
$ gcc function.c -g -pthread
$ sudo ./funclatency.sh $(pidof a.out) 'Foo'
$ sudo ./stackcount.sh $(pidof a.out) 'Foo'
```

```
$ cat alloc.c
#include <stdlib.h>
#include <unistd.h>

int main(void) {
  void *a[20];
  for (int i = 0; i < 20; ++i) {
    sleep(1);
    a[i] = malloc(1);
  }
  for (int i = 0; i < 20; ++i) {
    sleep(1);
    free(a[i]);
  }
  return 0;
}
$ gcc alloc.c -g -pthread
$ sudo ./memleak.sh $(pidof a.out)
```

## Useful links

In-depth description of the BPF internals from [Cilium](https://docs.cilium.io/en/latest/bpf).
Man pages for [bpf syscall](https://man7.org/linux/man-pages/man2/bpf.2.html)
and [bpf-helpers](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html).
Relevant parts in the Linux kernel source tree
[implementation](https://github.com/torvalds/linux/tree/master/kernel/bpf),
[user space library](https://github.com/torvalds/linux/tree/master/tools/lib/bpf),
[test](https://github.com/torvalds/linux/tree/master/tools/testing/selftests/bpf),
[samples](https://github.com/torvalds/linux/tree/master/samples/bpf),
[documentation](https://www.kernel.org/doc/html/latest/bpf/index.html),
[mailing list](https://lore.kernel.org/bpf).
