#include <getopt.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include "test_sockmap_listen.skel.h"


static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}


int main(int argc, char *argv[])
{
    struct test_sockmap_listen_bpf *skel;
    // struct bpf_link *link;
    int sockmap_fd;
    int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

    skel = test_sockmap_listen_bpf__open_and_load();
    if (!skel) {
            fprintf(stderr, "Failed to open BPF skeleton\n");
            return 1;
    }

    sockmap_fd = bpf_object__find_map_fd_by_name(skel->obj, "sock_map");
    if (!sockmap_fd) {
        fprintf(stderr, "Failed to find ebpf map `sock_map`");
        goto cleanup;
    }

    int idx = 0;
    int val = 1;
    bpf_map_update_elem(sockmap_fd, &idx, &val, BPF_ANY);

    struct bpf_program *prog_parser = bpf_object__find_program_by_name(skel->obj, "prog_stream_parser");
    if (!prog_parser) {
        fprintf(stderr, "Failed to find ebpf program `prog_stream_parser`");
        goto cleanup;
    }

    err = bpf_prog_attach(bpf_program__fd(prog_parser), sockmap_fd, BPF_SK_SKB_STREAM_PARSER, 0);
    if (err) {
        fprintf(stderr, "Failed to attach program `prog_stream_parser`");
        goto cleanup;
    }

    struct bpf_program *prog_verdict = bpf_object__find_program_by_name(skel->obj, "prog_stream_verdict");
    if (!prog_verdict) {
        fprintf(stderr, "Failed to find ebpf program `prog_stream_verdict`");
        goto cleanup;
    }

    err = bpf_prog_attach(bpf_program__fd(prog_verdict), sockmap_fd, BPF_SK_SKB_STREAM_VERDICT, 0);
    if (err) {
        fprintf(stderr, "Failed to attach program `prog_stream_verdict`");
        goto cleanup;
    }

    for (;;) {
        sleep(1);
    }

cleanup:
    test_sockmap_listen_bpf__destroy(skel);
    return 0;
}
