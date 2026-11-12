#include "kernel/types.h"
#include "kernel/stat.h"
#include "kernel/param.h"
#include "kernel/fcntl.h"
#include "user/user.h"

// budgettest [block]
//   (no arg) runaway test: 200 files, budget 50, refill 10, FAIL mode.
//            expected: 5 unlinks succeed.
//   block    8 files, same budget, BLOCK mode.
//            expected: 5 at once, then about one more per 100 ticks.
// All output is printed in group 0, because a drained group cannot even
// write to the console.

#define MAXN 200

static void
mkname(char *name, int i)
{
  name[0] = 'f';
  name[1] = '0' + i / 100;
  name[2] = '0' + (i / 10) % 10;
  name[3] = '0' + i % 10;
  name[4] = 0;
}

int
main(int argc, char *argv[])
{
  int mode = BUDGET_FAIL;
  int n = MAXN;
  int i, ok = 0, fd;
  int when[MAXN];
  char name[8];
  struct budgetinfo bi;

  if (argc > 1 && strcmp(argv[1], "block") == 0) {
    mode = BUDGET_BLOCK;
    n = 8;
  }

  mkname(name, 0);
  unlink(name);
  fd = open(name, O_CREATE | O_RDWR);
  if (fd < 0) {
    printf("cannot create %s\n", name);
    exit(1);
  }
  close(fd);
  for (i = 1; i < n; i++) {
    char first[8];
    mkname(first, 0);
    mkname(name, i);
    unlink(name);
    if (link(first, name) < 0) {
      printf("cannot link %s\n", name);
      exit(1);
    }
  }

  if (setbudget(1, 50, 10, mode) < 0) {
    printf("setbudget failed\n");
    exit(1);
  }

  setgroup(1);
  for (i = 0; i < n; i++) {
    mkname(name, i);
    if (unlink(name) == 0) {
      ok++;
      when[i] = uptime();
    } else {
      when[i] = -1;
    }
  }
  setgroup(0);

  printf("mode %s: %d of %d unlinks succeeded\n",
         mode == BUDGET_BLOCK ? "BLOCK" : "FAIL", ok, n);
  if (mode == BUDGET_BLOCK) {
    for (i = 0; i < n; i++)
      printf("  unlink %d done at tick +%d\n", i, when[i] - when[0]);
  }
  if (getbudget(1, &bi) == 0)
    printf("group 1: budget %d/%d allowed %d blocked %d refused %d\n",
           bi.budget, bi.max, bi.n_allowed, bi.n_blocked, bi.n_refused);

  // clean up whatever is left
  for (i = 0; i < n; i++) {
    mkname(name, i);
    unlink(name);
  }
  exit(0);
}
