#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

struct event {
  char comm[TASK_COMM_LEN];
  char fname[MAX_FILENAME_LEN];
};
