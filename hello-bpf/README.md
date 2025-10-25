## Compile the hello.bpf.c
clang -O2 -target bpf -g -c hello.bpf.c -o hello.bpf.o

## Compile the hello_loader.c
clang -o hello_loader hello_loader.c -lbpf

## Run the loader (requires root privileges)
sudo ./hello_loader

## View the output
sudo cat /sys/kernel/tracing/trace_pipe