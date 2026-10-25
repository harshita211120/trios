#include "kernel/types.h"
#include "user/user.h"

int
main(void)
{
  printf("setgroup(0) = %d\n", setgroup(0));
  printf("setgroup(-1) = %d\n", setgroup(-1));
  printf("setgroup(15) = %d\n", setgroup(15));
  exit(0);
}
