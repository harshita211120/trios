#include "kernel/types.h"
#include "kernel/stat.h"
#include "kernel/fcntl.h"
#include "user/user.h"

// Ported to the RISC-V tree. Opening inbox.txt taints this process;
// unlink() must then be denied by the kernel.
int
main(void)
{
  int fd;

  printf("\n=== Running Kernel Taint Verification Test ===\n");

  fd = open("inbox.txt", O_RDONLY);
  if (fd < 0) {
    printf("Failed to open inbox.txt\n");
    exit(1);
  }
  close(fd);

  printf("Attempting to unlink important.txt while tainted...\n");
  if (unlink("important.txt") < 0)
    printf("[SUCCESS] Kernel blocked unlink() call for tainted process.\n");
  else
    printf("[FAILURE] Kernel allowed unlink() call for tainted process.\n");

  exit(0);
}
