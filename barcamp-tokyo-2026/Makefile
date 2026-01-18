CLANG ?= clang
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

all: trace_open.bpf.o trace_open

trace_open.bpf.o: trace_open.bpf.c
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-c trace_open.bpf.c -o trace_open.bpf.o

trace_open: trace_open.c
	$(CLANG) -g -O2 -Wall \
		-o trace_open trace_open.c \
		-lbpf -lelf -lz

clean:
	rm -f trace_open.bpf.o trace_open

.PHONY: all clean
