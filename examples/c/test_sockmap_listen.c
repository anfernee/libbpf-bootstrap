#include <getopt.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include "test_sockmap_listen.skel.h"

/*
Create a cgroup first:

  mkdir -p /tmp/cgroupv2
  mount -t cgroup2 none /tmp/cgroupv2
  mkdir -p /tmp/cgroupv2/foo
  bash
  echo $$ >> /tmp/cgroupv2/foo/cgroup.procs

then
  ./test_sockmap_listen -c /tmp/cgroupv2 &
  nc localhost 55601

 sudo cat /sys/kernel/debug/tracing/trace_pipe


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
    struct test_sockmap_listen_bpf *skel;
    struct bpf_link *link;
    char* cgroup_path;
    int fd, sockmap_fd;
    // int err;
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


    skel = test_sockmap_listen_bpf__open_and_load();
    if (!skel) {
            fprintf(stderr, "Failed to open BPF skeleton\n");
            return 1;
    }

/*
    err = test_sockmap_listen_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to laod ebpf program");
        goto cleanup;
    }
*/

    sockmap_fd = bpf_object__find_map_fd_by_name(skel->obj, "sock_map");
    if (!sockmap_fd) {
        fprintf(stderr, "Failed to find ebpf map `sock_map`");
        goto cleanup;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(skel->obj, "prog_stream_parser");
    if (!prog) {
        fprintf(stderr, "Failed to find ebpf program `prog_stream_parser`");
        goto cleanup;
    }

    // It's wrong to attach to cgroup. It should be attached to a sockmap.
    link = bpf_program__attach_cgroup(prog, sockmap_fd);
    if (!link) {
        fprintf(stderr, "Failed to attach program `prog_stream_parser`");
        goto cleanup;
    }

    for (;;) {
        sleep(1);
    }

cleanup:
    test_sockmap_listen_bpf__destroy(skel);
    return 0;
}
