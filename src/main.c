#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "box.h"

#define MAX_ACTION_LENGTH 100
#define BOX_HELP "Usage: box <action> <directory>\n\
Actions:\n\
  create: Create a new box\n\
  wrap: Encrypt the box\n\
  unwrap: Decrypt the box\n\
"

int main(int argc, char *argv[]) {
  printf("Box v%s\n", B_VERSION);
  B_EXIT_CODE ec;
  B_BOX box;

  if (argc != 3) {
    printf("%s", BOX_HELP);
    exit(1);
  }

  char *action = argv[1];
  char *target = argv[2];

  target[B_PATH_MAX_LENGTH] = 0;
  ec = b_box_init(target, &box);

  if (ec != B_EC_SUCCESS) {
    printf("Error: Box init falied with exit code %d\n", ec);
    b_box_free(&box);
    exit(2);
  }

  if (strncmp(action, "create", MAX_ACTION_LENGTH) == 0) {
    ec = b_box_create(&box);

    if (ec != B_EC_SUCCESS) {
      printf("Error: Box init failed with exit code %d\n", ec);
      b_box_free(&box);
      exit(3);
    }

  }
  else if (strncmp(action, "wrap", MAX_ACTION_LENGTH) == 0) {
    ec = b_box_wrap(&box);

    if (ec != B_EC_SUCCESS) {
      printf("Error: Box wrap failed with exit code %d\n", ec);
      b_box_free(&box);
      exit(3);
    }

  }
  else if (strncmp(action, "unwrap", MAX_ACTION_LENGTH) == 0) {
    ec = b_box_unwrap(&box);

    if (ec != B_EC_SUCCESS) {
      printf("Error: Box unwrap failed with exit code %d\n", ec);
      b_box_free(&box);
      exit(3);
    }

  }
  else {
    printf("Error: Invalid action\n");
    b_box_free(&box);
    exit(4);
  }

  b_box_free(&box);
  return 0;
}
