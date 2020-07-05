cmake_minimum_required(VERSION 3.10)

project(bpf C)

add_library(loader
  loader.c
)

add_library(bpf
  bpf_entry.c
  bpf_return.c
)
