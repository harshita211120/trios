#define T_DIR    1 // Directory
#define T_FILE   2 // File
#define T_DEVICE 3 // Device

struct stat {
  int dev;     // File system's disk device
  uint ino;    // Inode number
  short type;  // Type of file
  short nlink; // Number of links to file
  uint64 size; // Size of file in bytes
};

// Snapshot of one process group's irreversibility budget (getbudget()).
struct budgetinfo {
  int used;      // has this group been configured?
  int budget;    // remaining budget right now
  int max;       // ceiling
  int refill;    // units added per 100 ticks
  int mode;      // BUDGET_BLOCK or BUDGET_FAIL
  int n_allowed; // priced calls that were charged and ran
  int n_blocked; // priced calls that had to sleep for a refill
  int n_refused; // priced calls rejected with -1
  int tainted;   // has any member of this group read untrusted data?
};
