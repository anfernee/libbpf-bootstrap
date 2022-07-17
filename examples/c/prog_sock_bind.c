#include <getopt.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include "prog_sock_bind.skel.h"


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
  struct prog_sock_bind_bpf *skel;
  struct bpf_link *link;
  char* cgroup_path;
  char c;
  int fd, err;

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

      skel = prog_sock_bind_bpf__open();
    if (!skel) {
            fprintf(stderr, "Failed to open BPF skeleton\n");
            return 1;
    }

    err = prog_sock_bind_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to laod ebpf program");
        goto cleanup;
    }

    // libbpf doesn't have attach fn defined for socket, noop!
    err = prog_sock_bind_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach program");
        goto cleanup;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(skel->obj, "bind_v4_prog");
    if (!prog) {
        fprintf(stderr, "Failed to find ebpf program `bind_v4_prog`");
        goto cleanup;
    }

    link = bpf_program__attach_cgroup(prog, fd);
    if (!link) {
        fprintf(stderr, "Failed to attach program `bind_v4_prog`");
        goto cleanup;
    }

    for (;;) {
        sleep(1);
    }
cleanup:
    prog_sock_bind_bpf__destroy(skel);

    return 0;

  return 0;
}
