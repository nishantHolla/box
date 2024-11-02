#include <stdio.h>
#include <string.h>
#include "box.h"
#include "test.h"

int test_case_passed = 0;
int test_case_length = 0;

const char *test_dir = "./dir";
const char *desc_file_path = "./dir/box_desc.txt";

int main(void) {
  FILE *desc_file = fopen(desc_file_path, "w");
  if (!desc_file_path) {
    printf("Failed to create desc file");
    return 1;
  }

  fprintf(desc_file, "\
my_box\n\
5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03\n\
5841b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03 20\n\
6841b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03 5\n\
7841b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03 10\n\
8841b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03 1\n\
9841b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03 2\n\
");

  fclose(desc_file);

  B_EXIT_CODE ec;
  B_BOX box;

  char root_path[B_PATH_MAX_LENGTH];
  b_path_abs(test_dir, root_path);

  TEST_CASE("b_box_init");

  ec = b_box_init(test_dir, &box);

  if (ec != B_EC_SUCCESS) {
    TEST_CASE_FAILED("Exit code: %d", ec);
  }
  else if (box.is_valid != 1) {
    TEST_CASE_FAILED("Is valid failed. Expected 0 got %d", box.is_valid);
  }
  else if (strncmp(box.name, "my_box", B_BOX_MAX_NAME_LENGTH) != 0) {
    TEST_CASE_FAILED("Name failed. Expected my_box got %s", box.name);
  }
  else if (strncmp(box.root_path, root_path, B_PATH_MAX_LENGTH) != 0) {
    TEST_CASE_FAILED("Root path failed. Expected %s got %s", root_path, box.root_path);
  }
  else {
    TEST_CASE_PASSED;
  }

  TEST_CASE("b_box_free");

  ec = b_box_free(&box);
  if (ec != B_EC_SUCCESS) {
    TEST_CASE_FAILED("Exit code: %d", ec);
  }
  else {
    TEST_CASE_PASSED;
  }

  TEST_RESULT;
  return 0;
}
