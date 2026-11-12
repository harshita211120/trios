#include "kernel/types.h"
#include "kernel/stat.h"
#include "kernel/param.h"
#include "user/user.h"

// budgetstat [gid]
// Print the irreversibility budget state of every configured process
// group, or of just one group if gid is given.

static void
show(int gid)
{
  struct budgetinfo bi;

  if (getbudget(gid, &bi) < 0) {
    fprintf(2, "budgetstat: bad group %d\n", gid);
    return;
  }
  if (!bi.used)
    return;
  printf("group %d: budget %d/%d refill %d/100 ticks mode %s allowed %d blocked %d refused %d tainted %d\n",
         gid, bi.budget, bi.max, bi.refill,
         bi.mode == BUDGET_BLOCK ? "BLOCK" : "FAIL", bi.n_allowed,
         bi.n_blocked, bi.n_refused, bi.tainted);
}

int
main(int argc, char *argv[])
{
  int g;

  if (argc > 1) {
    show(atoi(argv[1]));
    exit(0);
  }
  for (g = 0; g < NGROUP; g++)
    show(g);
  exit(0);
}
