#include "box.h"
#include "test.h"
#include <stdio.h>

int test_case_passed = 0;
int test_case_length = 0;

int main(void) {
  B_EXIT_CODE ec;
  FILE *desc_file = fopen(B_BOX_DESC_FILE, "w");
  fprintf(desc_file, "HELLO");

  TEST_CASE("b_box_check_ancestors");

  if ((ec = b_box_check_ancestors("./dir", NULL)) != B_EC_SUCCESS) {
    TEST_CASE_FAILED("Exit code: %d", ec);
  }
  else {
    fclose(desc_file);
    remove(B_BOX_DESC_FILE);
    if ((ec = b_box_check_ancestors("./dir", NULL)) == B_EC_SUCCESS) {
      TEST_CASE_FAILED("Exit code: %d", ec);
    }
    else {
      TEST_CASE_PASSED;
    }
  }

  TEST_CASE("b_box_check_descendants");

  if ((ec = b_box_check_descendants("./dir", NULL)) != B_EC_SUCCESS) {
    TEST_CASE_FAILED("Exit code: %d", ec);
  }
  else {
    TEST_CASE_PASSED;
  }

  TEST_RESULT;
  return 0;
}
