#!/usr/bin/env python3
"""
Apply the taint + budget kernel patches. Run from the project root:
    python3 apply_taint_patch.py
Safe to re-run: already-patched spots are skipped. Backups go to *.orig.
"""
import re
import shutil
import sys

problems = []


def load(path):
    with open(path) as f:
        return f.read()


def save(path, text):
    shutil.copyfile(path, path + ".orig")
    with open(path, "w") as f:
        f.write(text)


def sub_once(text, anchor, new, path, marker):
    """Replace anchor (must occur exactly once) unless marker is present."""
    if marker in text:
        print(f"  skip  {path}: {marker!r} already there")
        return text
    if text.count(anchor) != 1:
        problems.append(f"{path}: anchor not found exactly once: {anchor[:50]!r}")
        return text
    print(f"  patch {path}: {marker!r}")
    return text.replace(anchor, new)


# ---------------- kernel/proc.h ----------------
p = "kernel/proc.h"
t = load(p)
t = sub_once(t, "  int gid;              // Process group ID\n",
             "  int gid;              // Process group ID\n"
             "  int tainted;          // has this process read untrusted data?\n",
             p, "int tainted;")
save(p, t)

# ---------------- kernel/proc.c ----------------
p = "kernel/proc.c"
t = load(p)
t = sub_once(t, "  p->gid = 0;\n  p->state = USED;\n",
             "  p->gid = 0;\n  p->tainted = 0;\n  p->state = USED;\n",
             p, "p->tainted = 0;\n  p->state = USED;")
t = sub_once(t, "  p->gid = 0;\n  p->name[0] = 0;\n",
             "  p->gid = 0;\n  p->tainted = 0;\n  p->name[0] = 0;\n",
             p, "p->tainted = 0;\n  p->name[0] = 0;")
t = sub_once(t, "  np->gid = p->gid;\n",
             "  np->gid = p->gid;\n  np->tainted = p->tainted; // taint survives fork\n",
             p, "np->tainted")
save(p, t)

# ---------------- kernel/stat.h ----------------
p = "kernel/stat.h"
t = load(p)
t = sub_once(t, "  int n_refused; // priced calls rejected with -1\n};",
             "  int n_refused; // priced calls rejected with -1\n"
             "  int tainted;   // has any member of this group read untrusted data?\n};",
             p, "int tainted;")
save(p, t)

# ---------------- kernel/defs.h ----------------
p = "kernel/defs.h"
t = load(p)
t = sub_once(t, "int             budget_get(int, struct budgetinfo*);\n",
             "int             budget_get(int, struct budgetinfo*);\n"
             "void            group_taint(int);\n"
             "int             group_is_tainted(int);\n",
             p, "group_taint")
save(p, t)

# ---------------- kernel/budget.c ----------------
p = "kernel/budget.c"
t = load(p)
t = sub_once(
    t,
    "#define COST_EXEC_FOREIGN  5  // exec() of a file another group created\n",
    "#define COST_EXEC_FOREIGN  5  // exec() of a file another group created\n"
    "\n// Prices once the caller or its group has read untrusted data.\n"
    "#define COST_UNLINK_TAINTED       100\n"
    "#define COST_WRITE_CONSOLE_TAINT  3\n"
    "#define COST_WRITE_OTHER_TAINT    9\n"
    "#define COST_EXEC_FOREIGN_TAINT   25\n",
    p, "COST_UNLINK_TAINTED")
t = sub_once(t, "  int n_refused;\n};",
             "  int n_refused;\n  int tainted;         // a member read untrusted data\n};",
             p, "int tainted;         // a member")
t = sub_once(t, "    groups[i].n_refused = 0;\n  }",
             "    groups[i].n_refused = 0;\n    groups[i].tainted = 0;\n  }",
             p, "groups[i].tainted")
t = sub_once(t, "  g->n_refused = 0;\n  release(&g->lock);\n  return 0;",
             "  g->n_refused = 0;\n  g->tainted = 0;\n  release(&g->lock);\n  return 0;",
             p, "g->tainted = 0;")
t = sub_once(t, "  bi->n_refused = g->n_refused;\n",
             "  bi->n_refused = g->n_refused;\n  bi->tainted = g->tainted;\n",
             p, "bi->tainted")

NEW_COST = '''int
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

'''
if "int taint = p->tainted" in t:
    print(f"  skip  {p}: syscall_cost already replaced")
else:
    m = re.search(r"int\nsyscall_cost\(int num, struct proc \*p\)\n\{.*?\n\}\n\n"
                  r"(?=// setbudget\(\))", t, re.S)
    if not m:
        problems.append(f"{p}: could not locate syscall_cost()")
    else:
        print(f"  patch {p}: syscall_cost()")
        t = t[:m.start()] + NEW_COST + t[m.end():]

HELPERS = '''
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
'''
if "group_taint(int gid)" in t:
    print(f"  skip  {p}: helpers already there")
else:
    print(f"  patch {p}: group_taint / group_is_tainted")
    t = t.rstrip("\n") + "\n" + HELPERS
save(p, t)

# ---------------- kernel/sysfile.c ----------------
p = "kernel/sysfile.c"
t = load(p)
t = sub_once(
    t,
    "  char name[DIRSIZ], path[MAXPATH];\n  uint off;\n\n"
    "  if (argstr(0, path, MAXPATH) < 0)\n    return -1;\n\n"
    "  begin_op();\n  if ((dp = nameiparent(path, name)) == 0) {",
    "  char name[DIRSIZ], path[MAXPATH];\n  uint off;\n  struct proc *p = myproc();\n\n"
    "  if (argstr(0, path, MAXPATH) < 0)\n    return -1;\n\n"
    "  if (p->tainted) {\n"
    "    printk(\"[KERNEL DENIAL] Process %d (%s) is TAINTED. unlink() blocked by kernel!\\n\",\n"
    "           p->pid, p->name);\n"
    "    return -1;\n  }\n\n"
    "  begin_op();\n  if ((dp = nameiparent(path, name)) == 0) {",
    p, "[KERNEL DENIAL]")
t = sub_once(
    t,
    "  iunlock(ip);\n  end_op();\n\n  return fd;\n}",
    "  iunlock(ip);\n  end_op();\n\n"
    "  if (strncmp(path, \"inbox.txt\", MAXPATH) == 0 ||\n"
    "      strncmp(path, \"/inbox.txt\", MAXPATH) == 0) {\n"
    "    struct proc *tp = myproc();\n"
    "    tp->tainted = 1;\n"
    "    group_taint(tp->gid);\n"
    "    printk(\"[KERNEL TAINT] Process %d (%s) opened untrusted inbox.txt -> TAINTED.\\n\",\n"
    "           tp->pid, tp->name);\n  }\n\n"
    "  return fd;\n}",
    p, "[KERNEL TAINT]")
save(p, t)

print()
if problems:
    print("PROBLEMS (those spots were NOT patched):")
    for x in problems:
        print("  -", x)
    sys.exit(1)
print("All patches applied. Now run: make clean && make fs.img")
