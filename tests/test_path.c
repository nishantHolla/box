#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "test.h"
#include "box.h"

int test_case_passed = 0;
int test_case_length = 0;

const char *test_path = "../..";
const char *test_dir_path = "test_dir";
const char *test_file_path = "test_dir/test_file.txt";
const char *test_sym_file_path = "test_dir/test_sym_file.txt";
const char *test_sym_dir_path = "test_dir/test_sym_dir";

int main(void) {
  B_EXIT_CODE ec;

  TEST_CASE("b_path_abs");

  char abs_path[B_PATH_MAX_LENGTH];
  ec = b_path_abs(test_path, abs_path);
  if (ec != B_EC_SUCCESS) {
    TEST_CASE_FAILED("Exit code: %d", ec);
  }
  else {
    TEST_CASE_PASSED;
  }

  TEST_OUTPUT("input path", "%s", test_path);
  TEST_OUTPUT("output path", "%s", abs_path);

  TEST_CASE("b_path_stat");

  if (mkdir(test_dir_path, 0755) != 0) {
    printf("Failed to create test directory");
    return 1;
  }

  FILE *test_file = fopen(test_file_path, "w");
  if (!test_file) {
    printf("Failed to create test file");
    return 1;
  }
  fprintf(test_file, "hello");

  if (symlink("./test_file.txt", test_sym_file_path) != 0) {
    printf("Failed to create sym link file");
    return 1;
  }

  if (symlink("../test_dir", test_sym_dir_path) != 0) {
    printf("Failed to create sym link dir");
    return 1;
  }

  B_PATH_STAT st;

  if ( (st = b_path_stat(test_file_path)) != B_PATH_FILE) {
    TEST_CASE_FAILED("File expected %d got %d", B_PATH_FILE, st);
  }
  else if ((st = b_path_stat(test_dir_path)) != B_PATH_DIR) {
    TEST_CASE_FAILED("Dir expected %d got %d", B_PATH_DIR, st);
  }
  else if ((st = b_path_stat(test_sym_file_path)) != B_PATH_LINK_FILE) {
    TEST_CASE_FAILED("Sym file expected %d got %d", B_PATH_LINK_FILE, st);
  }
  else if ((st = b_path_stat(test_sym_dir_path)) != B_PATH_LINK_DIR) {
    TEST_CASE_FAILED("Sym dir expected %d got %d", B_PATH_LINK_DIR, st);
  }
  else {
    TEST_CASE_PASSED;
  }

  TEST_CASE("b_path_parent");

  char parent_test[B_PATH_MAX_LENGTH];
  b_path_parent("/test/dir", parent_test);
  if (strncmp(parent_test, "/test", B_PATH_MAX_LENGTH) != 0) {
    TEST_CASE_FAILED("Expected %s got %s", "/test", parent_test);
  }
  else {
    TEST_CASE_PASSED;
  }

  fclose(test_file);
  TEST_RESULT;
  return 0;
}

