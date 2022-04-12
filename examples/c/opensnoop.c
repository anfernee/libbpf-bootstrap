#include "opensnoop.skel.h"
#include "opensnoop.h"

static int handle_event(void *ctx, void *data, size_t data_sz)
{
  const struct event *e = data;

  printf("event command:'%s', filename: '%s'\n", e->comm, e->fname);
  return 0;
}

int main(int argc, char **argv) {
  struct opensnoop_bpf *skel;
  struct ring_buffer *rb;
  int err;

  skel = opensnoop_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF skeleton\n");
    return 1;
  }

  err = opensnoop_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load and verify BPF skeleton\n");
    goto cleanup;
  }

  err = opensnoop_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }

  rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
  if (!rb) {
    err = -1;
    fprintf(stderr, "Failed to new ring buffer\n");
    goto cleanup;
  }

  while(err != -EINTR) {
    err = ring_buffer__poll(rb, 100);
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
  }

cleanup:
  ring_buffer__free(rb);
  opensnoop_bpf__detach(skel);
  return -err;
}