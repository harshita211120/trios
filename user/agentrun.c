#include "kernel/types.h"
#include "user/user.h"

// agentrun <gid> <cmd> [args...]
// Join process group gid, then exec the command. A process can only change
// its own group, so the host uses this wrapper to run each tool call inside
// the agent's budgeted group.
int
main(int argc, char *argv[])
{
  if (argc < 3) {
    fprintf(2, "usage: agentrun gid cmd [args...]\n");
    exit(1);
  }
  if (setgroup(atoi(argv[1])) < 0) {
    fprintf(2, "agentrun: bad group\n");
    exit(1);
  }
  exec(argv[2], &argv[2]);
  fprintf(2, "agentrun: exec %s failed\n", argv[2]);
  exit(1);
}
