#include <bpf/libbpf.h>  // Main libbpf API.
#include <stdio.h>       
#include <unistd.h>      

#define ERR(fmt, ...) fprintf(stderr, fmt "\n", ##__VA_ARGS__)

int main(int argc, char **argv) {
    // Open the BPF object file.
    struct bpf_object *obj = bpf_object__open_file("hello.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        ERR("Failed to open BPF object");
        return 1;
    }

    // Load all programs in the object into the kernel.
    if (bpf_object__load(obj) < 0) {
        ERR("Failed to load BPF object");
        bpf_object__close(obj);
        return 1;
    }

    // Find the program by its section name after loading.
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "hello_execve");
    if (!prog) {
        ERR("Failed to find BPF program");
        bpf_object__close(obj);
        return 1;
    }

    // Attach the program to the tracepoint.
    struct bpf_link *link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) {
        ERR("Failed to attach BPF program");
        bpf_object__close(obj);
        return 1;
    }

    printf("eBPF program loaded and attached! Run commands to trigger it.\n");
    printf("View output with: cat /sys/kernel/tracing/trace_pipe\n");

    // Keep the loader running to hold the attachment (press Ctrl+C to exit).
    while (1) {
        sleep(1);
    }

    // Cleanup (though we won't reach here in this example).
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}
