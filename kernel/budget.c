#include "types.h"
#include "riscv.h"
#include "param.h"
#include "spinlock.h"
#include "defs.h"

// Shared state for one process group.
struct group {
  struct spinlock lock;
  int used;
  int budget;          // remaining budget
  int max;             // maximum budget
  int refill;          // units added per 100 ticks
  int mode;            // BUDGET_BLOCK or BUDGET_FAIL
  uint last_refill;    // last refill time
  int n_allowed;
  int n_blocked;
  int n_refused;
};

// One shared budget per group.
struct group groups[NGROUP];

// Initialize all process groups.
// Group 0 is the default group.
void
budgetinit(void)
{
  int i;

  for (i = 0; i < NGROUP; i++) {
    initlock(&groups[i].lock, "group");

    groups[i].used = 0;
    groups[i].budget = 0;
    groups[i].max = 0;
    groups[i].refill = 0;
    groups[i].mode = BUDGET_FAIL;
    groups[i].last_refill = 0;

    groups[i].n_allowed = 0;
    groups[i].n_blocked = 0;
    groups[i].n_refused = 0;
  }

  // Group 0 is the default group for ordinary processes.
  // Give it a large budget until explicitly configured.
  groups[0].used = 1;
  groups[0].budget = 1000000000;
  groups[0].max = 1000000000;
  groups[0].refill = 0;
  groups[0].mode = BUDGET_FAIL;
}
