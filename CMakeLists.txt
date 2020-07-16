cmake_minimum_required(VERSION 3.10)

project(bpf C)

add_library(loader
  loader.c
  loader.h
  funclatency.c
)

add_library(bpf
  funclatency_entry.c
  funclatency_exit.c
)
