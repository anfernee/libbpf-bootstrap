#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <linux/filter.h>
#include <assert.h>
#include "prog_socket_filter.skel.h"
#include "socket.h"

#define SO_ATTACH_BPF		50

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char const *argv[])
{
  struct prog_socket_filter_bpf *skel;
  int sock;
  int err;

  skel = prog_socket_filter_bpf__open();
  if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
  }

  err = prog_socket_filter_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to laod ebpf program");
    goto cleanup;
  }

  // libbpf doesn't have attach fn defined for socket, noop!
  err = prog_socket_filter_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach program");
    goto cleanup;
  }

  struct bpf_program *prog = bpf_object__find_program_by_name(skel->obj, "bpf_prog");
  if (!prog) {
    fprintf(stderr, "Failed to find ebpf program `bpf_prog`");
    goto cleanup;
  }

  int fd = bpf_program__fd(prog);

  sock = open_raw_sock("lo");
  assert(setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &fd, sizeof(fd)) == 0);

  printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");


	for (;;) {
		/* trigger our BPF program */
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
  prog_socket_filter_bpf__destroy(skel);
  return -err;
}
