#include "types.h"
#include "riscv.h"
#include "param.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "proc.h"
#include "defs.h"
#include "stat.h"
#include "fs.h"
#include "file.h"
#include "syscall.h"

// Syscall cost table (irreversibility units).
#define COST_UNLINK        10 // unlink() destroys a file
#define COST_WRITE_CONSOLE 1  // write() to the console, per call
#define COST_WRITE_OWN     0  // write() to a file my own group created
#define COST_WRITE_OTHER   3  // write() to any other file
#define COST_EXEC_FOREIGN  5  // exec() of a file another group created

// Prices once the caller or its group has read untrusted data.
#define COST_UNLINK_TAINTED       100
#define COST_WRITE_CONSOLE_TAINT  3
#define COST_WRITE_OTHER_TAINT    9
#define COST_EXEC_FOREIGN_TAINT   25

#define REFILL_PERIOD 100 // ticks per refill period

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
  int tainted;         // a member read untrusted data
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
    groups[i].tainted = 0;
  }

  // Group 0 is the default group for ordinary processes.
  // Give it a large budget until explicitly configured.
  groups[0].used = 1;
  groups[0].budget = 1000000000;
  groups[0].max = 1000000000;
  groups[0].refill = 0;
  groups[0].mode = BUDGET_FAIL;
}

// Lazy refill: top up g->budget for every whole refill period that has
// passed since g->last_refill. Called with g->lock held.
//
// ticks is written by the timer interrupt under tickslock, so it is read
// under tickslock too (the same way sys_uptime does). Lock order is always
// g->lock -> tickslock -> p->lock; nothing takes them the other way round.
static void
refill(struct group *g)
{
  uint now, elapsed, periods;

  acquire(&tickslock);
  now = ticks;
  release(&tickslock);

  elapsed = now - g->last_refill; // uint: survives wraparound
  periods = elapsed / REFILL_PERIOD;

  if (periods > 0) {
    // Compute in 64 bits so a long idle time times a big refill rate
    // cannot overflow, then clamp to the ceiling.
    uint64 add = (uint64)periods * (uint64)g->refill;
    uint64 room = g->budget < g->max ? (uint64)(g->max - g->budget) : 0;

    if (add >= room)
      g->budget = g->max;
    else
      g->budget += (int)add;

    // Advance by whole periods only. Setting last_refill = ticks would
    // throw away the remainder and make the refill rate drift slow.
    g->last_refill += periods * REFILL_PERIOD;
  }
}

// Charge `cost` units to group gid BEFORE the syscall does its work.
// Returns 0 if the call may proceed, -1 if it must be refused.
//
// A cost of 0 means the call isn't a priced action: it is neither
// charged nor counted, so n_allowed/n_blocked/n_refused only count calls
// that the cost table actually prices.
int
charge(int gid, int cost)
{
  struct group *g;
  struct proc *p = myproc();
  int blocked = 0;

  if (cost <= 0)
    return 0;
  if (gid < 0 || gid >= NGROUP)
    return -1;

  g = &groups[gid];
  acquire(&g->lock);

  if (!g->used) { // group was never given a budget: unlimited
    release(&g->lock);
    return 0;
  }

  refill(g);

  while (g->budget < cost) { // while, NOT if
    // Refuse at once in FAIL mode. Also refuse in BLOCK mode when waiting
    // can never help (no refill, or the cost exceeds the ceiling) rather
    // than sleeping forever.
    if (g->mode == BUDGET_FAIL || g->refill <= 0 || cost > g->max) {
      g->n_refused++;
      release(&g->lock);
      return -1;
    }

    // A killed process must not sleep here forever.
    if (killed(p)) {
      release(&g->lock);
      return -1;
    }

    if (!blocked) { // count calls that blocked, not wakeups
      g->n_blocked++;
      blocked = 1;
    }

    // Sleep until the next tick, then re-check. Another process in this
    // same group may wake first and take the refilled budget, which is
    // exactly why this is a loop. sleep_prepare() runs while g->lock is
    // still held, so a tick between release() and sleep() is not lost.
    sleep_prepare(&ticks);
    release(&g->lock);
    sleep();
    acquire(&g->lock);

    refill(g);
  }

  g->budget -= cost;
  g->n_allowed++;
  release(&g->lock);
  return 0;
}

// Look up the cost of system call `num` for process p, from its arguments.
// Called from syscall() before the call runs, with no locks held.
int
syscall_cost(int num, struct proc *p)
{
  int taint = p->tainted || group_is_tainted(p->gid);

  switch (num) {
  case SYS_unlink:
    if (p->tainted)
      return 0; // sys_unlink will deny it; don't spend budget
    return taint ? COST_UNLINK_TAINTED : COST_UNLINK;

  case SYS_write: {
    int fd;
    struct file *f;

    argint(0, &fd);
    if (fd < 0 || fd >= NOFILE || (f = p->ofile[fd]) == 0)
      return 0; // bad fd: write will fail by itself, nothing to undo
    if (f->type == FD_DEVICE)
      return f->major == CONSOLE
               ? (taint ? COST_WRITE_CONSOLE_TAINT : COST_WRITE_CONSOLE)
               : 0;
    if (f->type == FD_INODE) {
      if (f->ip->creator == (uint)p->gid)
        return COST_WRITE_OWN;
      return taint ? COST_WRITE_OTHER_TAINT : COST_WRITE_OTHER;
    }
    return 0; // pipes are not files on disk
  }

  case SYS_exec: {
    char path[MAXPATH];
    struct inode *ip;
    int cost = 0;

    if (argstr(0, path, MAXPATH) < 0)
      return 0; // kexec will reject the bad path itself
    begin_op();
    if ((ip = namei(path)) == 0) {
      end_op();
      return 0;
    }
    ilock(ip); // loads ip->creator from disk if needed
    if (ip->type == T_FILE && ip->creator != (uint)p->gid)
      cost = taint ? COST_EXEC_FOREIGN_TAINT : COST_EXEC_FOREIGN;
    iunlockput(ip);
    end_op();
    return cost;
  }

  default:
    return 0;
  }
}

// setbudget(): (re)configure group gid. The group starts full and its
// statistics restart from zero. Returns 0, or -1 on bad arguments.
int
budget_set(int gid, int max, int refill, int mode)
{
  struct group *g;

  if (gid < 0 || gid >= NGROUP || max < 0 || refill < 0)
    return -1;
  if (mode != BUDGET_BLOCK && mode != BUDGET_FAIL)
    return -1;

  g = &groups[gid];
  acquire(&g->lock);
  g->used = 1;
  g->max = max;
  g->budget = max;
  g->refill = refill;
  g->mode = mode;
  acquire(&tickslock);
  g->last_refill = ticks;
  release(&tickslock);
  g->n_allowed = 0;
  g->n_blocked = 0;
  g->n_refused = 0;
  g->tainted = 0;
  release(&g->lock);
  return 0;
}

// Snapshot group gid into *bi (for budgetstat). The budget shown includes
// any refill that is already due. Returns 0, or -1 for a bad gid.
int
budget_get(int gid, struct budgetinfo *bi)
{
  struct group *g;

  if (gid < 0 || gid >= NGROUP)
    return -1;

  g = &groups[gid];
  acquire(&g->lock);
  if (g->used)
    refill(g);
  bi->used = g->used;
  bi->budget = g->budget;
  bi->max = g->max;
  bi->refill = g->refill;
  bi->mode = g->mode;
  bi->n_allowed = g->n_allowed;
  bi->n_blocked = g->n_blocked;
  bi->n_refused = g->n_refused;
  bi->tainted = g->tainted;
  release(&g->lock);
  return 0;
}

// Mark group gid as having read untrusted data. Group 0 is the default group
// for every ordinary process, so tainting it would taint the whole system;
// it is deliberately ignored.
void
group_taint(int gid)
{
  struct group *g;

  if (gid <= 0 || gid >= NGROUP)
    return;
  g = &groups[gid];
  acquire(&g->lock);
  g->tainted = 1;
  release(&g->lock);
}

int
group_is_tainted(int gid)
{
  struct group *g;
  int t;

  if (gid <= 0 || gid >= NGROUP)
    return 0;
  g = &groups[gid];
  acquire(&g->lock);
  t = g->tainted;
  release(&g->lock);
  return t;
}
