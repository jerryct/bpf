cmake_minimum_required(VERSION 3.10)

project(bpf C)

add_library(bpf
  libbpf/bpf.c
  libbpf/bpf.h
)

add_library(loader
  conditions.h
  loader.c
  loader.h
  symbolizer.c
  symbolizer.h
)
target_link_libraries(loader PRIVATE bpf)

add_executable(funclatency funclatency.c)
target_link_libraries(funclatency PRIVATE loader)

add_executable(memleak memleak.c memleak.h)
target_link_libraries(memleak PRIVATE loader)

add_library(kernels
  bpf_helpers.h
  bpf_tracing.h
  funclatency_kernel.c
  memleak.h
  memleak_kernel.c
)
