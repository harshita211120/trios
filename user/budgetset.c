#include "kernel/types.h"
#include "kernel/param.h"
#include "user/user.h"

// budgetset <gid> <max> <refill_per_100_ticks> <fail|block>
// Shell front end for the setbudget() system call. Also clears the group's
// taint flag and statistics.
int
main(int argc, char *argv[])
{
  int mode;

  if (argc != 5) {
    fprintf(2, "usage: budgetset gid max refill fail|block\n");
    exit(1);
  }
  mode = strcmp(argv[4], "block") == 0 ? BUDGET_BLOCK : BUDGET_FAIL;
  if (setbudget(atoi(argv[1]), atoi(argv[2]), atoi(argv[3]), mode) < 0) {
    fprintf(2, "budgetset: bad arguments\n");
    exit(1);
  }
  exit(0);
}
