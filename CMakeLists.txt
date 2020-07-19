cmake_minimum_required(VERSION 3.10)

project(bpf C)

add_library(loader
  libbpf/bpf.c
  libbpf/bpf.h
  loader.c
  loader.h
)

add_executable(funclatency funclatency.c)
target_link_libraries(funclatency PRIVATE loader)

add_library(bpf
  bpf_helpers.h
  bpf_tracing.h
  funclatency_entry.c
  funclatency_exit.c
)
