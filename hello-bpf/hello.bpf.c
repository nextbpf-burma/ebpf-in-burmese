#include <linux/bpf.h>      // Core eBPF definitions.
#include <bpf/bpf_helpers.h> // Helper functions like bpf_printk.

// Define the section where this program will be placed. 
// "tracepoint/syscalls/sys_enter_execve" tells the loader to attach this 
// to the sys_enter_execve tracepoint, which fires on execve system calls.
SEC("tracepoint/syscalls/sys_enter_execve")
int hello_execve(struct trace_event_raw_sys_enter *ctx) {
    // bpf_printk is a helper to log messages to the kernel trace buffer.
    // It's like printf but for eBPF. The message can be viewed via 
    // /sys/kernel/tracing/trace_pipe.
    bpf_printk("Hello, eBPF!\n");
    
    // eBPF programs must return an integer. 0 means success/no action.
    return 0;
}

// eBPF programs require a license string. "GPL" is common for compatibility 
// with the Linux kernel.
char LICENSE[] SEC("license") = "GPL";
