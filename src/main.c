#include <openssl/sha.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "box.h"

int main(void) {
  printf("Box v%s\n", B_VERSION);
  printf("Hello, World.\n");

  B_BOX box;
  b_box_init("./dir", &box);
  b_box_create(&box);
  b_box_free(&box);
  return 0;
}
