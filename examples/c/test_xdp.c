#include <unistd.h>
#include <bpf/libbpf.h>
#include "test_xdp.skel.h"

#define IFINDEX_LO 1

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char const *argv[])
{
  struct test_xdp_bpf *skel;
  struct bpf_program *prog;
  struct bpf_link *link;

  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

  skel = test_xdp_bpf__open_and_load();
  if (!skel) {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;
  }

  prog = bpf_object__find_program_by_name(skel->obj, "_xdp_tx_iptunnel");
  if (!prog) {
    fprintf(stderr, "Failed to find BPF program\n");
    return 1;
  }

  link = bpf_program__attach_xdp(prog, IFINDEX_LO);
  if (!link) {
    fprintf(stderr, "Failed to attach program `bpf_bufs`");
    goto cleanup;
  }

  for (;;)
  {
    sleep(1);
  }

cleanup:

  test_xdp_bpf__destroy(skel);
  return 0;
}
