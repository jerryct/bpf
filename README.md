# bpf

Pre
```
sudo apt install xxd clang-10 llvm-10
```

```
sudo sh -c "echo 'p:funclatency_entry sys_clone' >> /sys/kernel/debug/tracing/kprobe_events"
sudo cat /sys/kernel/debug/tracing/events/kprobes/funclatency_entry/id
```
