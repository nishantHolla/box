#include <openssl/sha.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "box.h"

int main(void) {
  printf("Box v%s\n", B_VERSION);
  printf("Hello, World.\n");
  B_EXIT_CODE ec;

  B_BOX box;
  b_box_init("./dir", &box);
  ec = b_box_wrap(&box);
  printf("Exit code: %d\n", ec);
  b_box_free(&box);
  return 0;
}
