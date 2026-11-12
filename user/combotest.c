#include "kernel/types.h"
#include "kernel/stat.h"
#include "kernel/param.h"
#include "kernel/fcntl.h"
#include "user/user.h"

// Combined test: taint tracking + irreversibility budget.
//
// All output happens in group 0. A group-1 console write costs budget
// (and more once tainted), so results are collected first and printed after
// setgroup(0).
//
// Child exit codes: 0 = unlink was blocked (good), 1 = unlink succeeded (bad),
// 2 = setup error (could not open inbox.txt).

#define GID    1
#define NFILES 10

static char *names[NFILES] = {"t0", "t1", "t2", "t3", "t4",
                              "t5", "t6", "t7", "t8", "t9"};

static void
taint_self(void)
{
  int fd = open("inbox.txt", O_RDONLY);
  if (fd < 0)
    exit(2);
  close(fd);
}

static int
report(char *what, int ok)
{
  if (ok)
    printf("  [PASS] %s\n", what);
  else
    printf("  [FAIL] %s\n", what);
  return ok;
}

int
main(void)
{
  struct budgetinfo bi;
  int i, n, st, pid, r1, fd;
  int all = 1;

  printf("\n=== Combined taint + budget test ===\n");

  for (i = 0; i < NFILES; i++) {
    fd = open(names[i], O_CREATE | O_RDWR);
    if (fd < 0) {
      printf("setup: cannot create %s\n", names[i]);
      exit(1);
    }
    close(fd);
  }
  if (setbudget(GID, 50, 10, BUDGET_FAIL) < 0) {
    printf("setup: setbudget failed\n");
    exit(1);
  }

  // Phase 1: clean process, clean group. unlink costs 10 and is allowed.
  setgroup(GID);
  r1 = unlink(names[0]);
  setgroup(0);
  all &= report("clean process, clean group: unlink allowed (cost 10)", r1 == 0);

  // Phase 2: a sibling taints the group. A clean member of the group is not
  // hard-denied, but its unlink now costs 100 > max 50, so the budget
  // refuses it.
  pid = fork();
  if (pid < 0) {
    printf("fork failed\n");
    exit(1);
  }
  if (pid == 0) {
    setgroup(GID);
    taint_self();
    exit(0);
  }
  wait(&st);
  all &= report("setup: sibling tainted the group", st == 0);

  setgroup(GID);
  n = 0;
  for (i = 1; i <= 3; i++)
    if (unlink(names[i]) == 0)
      n++;
  setgroup(0);
  all &= report("clean sibling in tainted group: unlink refused by budget", n == 0);

  // Phase 3: a tainted process is hard-denied by sys_unlink.
  pid = fork();
  if (pid < 0) {
    printf("fork failed\n");
    exit(1);
  }
  if (pid == 0) {
    setgroup(GID);
    taint_self();
    exit(unlink(names[4]) < 0 ? 0 : 1);
  }
  wait(&st);
  all &= report("tainted process: unlink denied by kernel", st == 0);

  // Phase 4: taint is inherited across fork.
  pid = fork();
  if (pid < 0) {
    printf("fork failed\n");
    exit(1);
  }
  if (pid == 0) {
    int gpid;
    int gst = 1;
    setgroup(GID);
    taint_self();
    gpid = fork();
    if (gpid == 0)
      exit(unlink(names[5]) < 0 ? 0 : 1); // grandchild never tainted itself
    wait(&gst);
    exit(gst);
  }
  wait(&st);
  all &= report("child of tainted process: unlink denied (taint inherited)", st == 0);

  // Nothing but t0 should be gone.
  n = 0;
  for (i = 1; i <= 5; i++) {
    fd = open(names[i], O_RDONLY);
    if (fd >= 0) {
      n++;
      close(fd);
    }
  }
  all &= report("t1..t5 all still exist", n == 5);

  if (getbudget(GID, &bi) < 0) {
    printf("getbudget failed\n");
    exit(1);
  }
  printf("  group %d: budget %d/%d allowed %d refused %d tainted %d\n", GID,
         bi.budget, bi.max, bi.n_allowed, bi.n_refused, bi.tainted);
  all &= report("stats: allowed 1, refused 3, group tainted",
                bi.n_allowed == 1 && bi.n_refused == 3 && bi.tainted == 1);

  for (i = 1; i < NFILES; i++)
    unlink(names[i]);

  if (all)
    printf("combotest: ALL PASSED\n");
  else
    printf("combotest: SOME FAILED\n");
  exit(all ? 0 : 1);
}
