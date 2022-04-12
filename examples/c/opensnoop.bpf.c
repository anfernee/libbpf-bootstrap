#include "vmlinux.h"
#include "opensnoop.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tp/syscalls/sys_enter_open")
int handle_tp(struct trace_event_raw_sys_enter *ctx) {
  struct task_struct *task;
  struct event *e;
  const char *filename = (const char *)ctx->args[0];
  int flags = ctx->args[1];

  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e)
    return 0;


  task = (struct task_struct*)bpf_get_current_task();
  bpf_get_current_comm(&e->comm, sizeof(e->comm));
  bpf_probe_read_str(&e->fname, sizeof(e->fname), filename);


  // If not submit ring buffer, verifier will raise the following error:
  //
  // Unreleased reference id=2 alloc_insn=4
  bpf_ringbuf_submit(e, 0);
  return 0;
}