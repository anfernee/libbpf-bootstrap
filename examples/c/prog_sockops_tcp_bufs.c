#include <getopt.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include "prog_sockops_tcp_bufs.skel.h"

/*
Create a cgroup first:

  mkdir -p /tmp/cgroupv2
  mount -t cgroup2 none /tmp/cgroupv2
  mkdir -p /tmp/cgroupv2/foo
  bash
  echo $$ >> /tmp/cgroupv2/foo/cgroup.procs

then
  ./prog_sockops_tcp_bufs -c /tmp/cgroupv2 &
  nc localhost 55601

 sudo cat /sys/kernel/debug/tracing/trace_pipe
    nc-39218   [000] d... 17494.278169: bpf_trace_printk: skops->op 3
    nc-39218   [000] d... 17494.278183: bpf_trace_printk: Returning 0
    nc-39218   [000] d... 17494.278187: bpf_trace_printk: skops->op 2
    nc-39218   [000] d... 17494.278188: bpf_trace_printk: Returning 40
    nc-39218   [000] d... 17494.278189: bpf_trace_printk: skops->op 1
    nc-39218   [000] d... 17494.278190: bpf_trace_printk: Returning -1
    nc-39218   [000] d... 17494.278193: bpf_trace_printk: skops->op 6
    nc-39218   [000] d... 17494.278195: bpf_trace_printk: Returning -1

*/

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static void print_usage(char *prog_name) {
    const char *usage =
    "Usage:\n"
    "\t%s -c CGROUP_PATH\n";

    printf(usage, prog_name);
}


int main(int argc, char *argv[])
{
    struct prog_sockops_tcp_bufs_bpf *skel;
    struct bpf_link *link;
    char* cgroup_path;
    int fd;
    int err;
    int c;

    while ((c = getopt (argc, argv, "c:")) != -1) {
        switch (c)
        {
        case 'c':
            cgroup_path = optarg;
            break;

        default:
            print_usage(argv[0]);
            break;
        }
    }

    if (!cgroup_path) {
        print_usage(argv[0]);
        return -1;
    }

    printf("cgroup path: %s\n", cgroup_path);
    fd = open(cgroup_path, O_DIRECTORY | O_RDONLY);
    if (fd < 0) {
        perror("Failed to open directory");
        return -1;
    }

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

    skel = prog_sockops_tcp_bufs_bpf__open();
    if (!skel) {
            fprintf(stderr, "Failed to open BPF skeleton\n");
            return 1;
    }

    err = prog_sockops_tcp_bufs_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to laod ebpf program");
        goto cleanup;
    }

    // libbpf doesn't have attach fn defined for socket, noop!
    err = prog_sockops_tcp_bufs_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach program");
        goto cleanup;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(skel->obj, "bpf_bufs");
    if (!prog) {
        fprintf(stderr, "Failed to find ebpf program `bpf_bufs`");
        goto cleanup;
    }

    link = bpf_program__attach_cgroup(prog, fd);
    if (!link) {
        fprintf(stderr, "Failed to attach program `bpf_bufs`");
        goto cleanup;
    }

    for (;;) {
        sleep(1);
    }
cleanup:
    prog_sockops_tcp_bufs_bpf__destroy(skel);

    return 0;
}
