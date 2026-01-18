#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static volatile sig_atomic_t running = 1;

static void sig_handler(int sig)
{
    running = 0;
}

static int handle_event(void *ctx, void *data, size_t len)
{
    struct event {
        unsigned int pid;
        char comm[16];
        char filename[256];
    } *e = data;
    
    printf("%-16s %-6d %s\n", e->comm, e->pid, e->filename);
    return 0;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link = NULL;
    struct ring_buffer *rb = NULL;
    int map_fd, err;
    
    // Open and load BPF object
    obj = bpf_object__open_file("trace_open.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }
    
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        goto cleanup;
    }
    
    // Find the program
    prog = bpf_object__find_program_by_name(obj, "trace_openat");
    if (!prog) {
        fprintf(stderr, "Failed to find BPF program\n");
        goto cleanup;
    }
    
    // Attach program
    link = bpf_program__attach(prog);
    if (!link) {
        fprintf(stderr, "Failed to attach BPF program\n");
        goto cleanup;
    }
    
    // Set up ring buffer
    map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find ring buffer map\n");
        goto cleanup;
    }
    
    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    printf("%-16s %-6s %s\n", "PROCESS", "PID", "FILENAME");
    printf("Tracing file opens... Hit Ctrl-C to stop\n");
    
    while (running) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }
    
cleanup:
    ring_buffer__free(rb);
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return err != 0;
}
