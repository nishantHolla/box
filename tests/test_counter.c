#include <stdio.h>
#include "box.h"
#include "test.h"

int test_case_passed = 0;
int test_case_length = 0;

const uchar_t key1[B_COUNTER_KEY_LENGTH] = {
  0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x11, 0x12, 
  0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 
  0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22,
  0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A
};

const uchar_t key2[B_COUNTER_KEY_LENGTH] = {
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
  0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 
  0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
  0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
};


int main(void) {
  B_EXIT_CODE ec;
  B_COUNTER counter;

  TEST_CASE("b_counter_init");

  ec = b_counter_init(&counter);
  if (ec != B_EC_SUCCESS) {
    TEST_CASE_FAILED("Exit code: %d", ec);
  }
  else {
    TEST_CASE_PASSED;
  }

  TEST_CASE("b_counter_add");

  ec = b_counter_add(key1, &counter);
  if (ec != B_EC_SUCCESS) {
    TEST_CASE_FAILED("Exit code: %d", ec);
  }
  else {
    TEST_CASE_PASSED;
  }

  TEST_CASE("b_counter_count");

  B_COUNTER_BUCKET *test_bucket;
  int count = b_counter_count(key1, &counter, &test_bucket);
  if (count != 1) {
    TEST_CASE_FAILED("Expected 1 got %d", count);
  }
  else if (!test_bucket) {
    TEST_CASE_FAILED("Did not recieve bucket");
  }
  else if (test_bucket->count != 1) {
    TEST_CASE_FAILED("Recieved bucket is incorrect");
  }
  else {
    TEST_CASE_PASSED;
  }

  TEST_CASE("b_counter_add");

  ec = b_counter_add(key1, &counter);
  if (ec != B_EC_SUCCESS) {
    TEST_CASE_FAILED("Exit code: %d", ec);
  }
  else {
    TEST_CASE_PASSED;
  }

  TEST_CASE("b_counter_count");

  count = b_counter_count(key1, &counter, NULL);
  if (count != 2) {
    TEST_CASE_FAILED("Expected 2 got %d", count);
  }
  else {
    TEST_CASE_PASSED;
  }

  TEST_CASE("b_counter_add");

  ec = b_counter_add(key2, &counter);
  if (ec != B_EC_SUCCESS) {
    TEST_CASE_FAILED("Exit code: %d", ec);
  }
  else {
    TEST_CASE_PASSED;
  }


  TEST_CASE("b_counter_add");

  ec = b_counter_add(key2, &counter);
  if (ec != B_EC_SUCCESS) {
    TEST_CASE_FAILED("Exit code: %d", ec);
  }
  else {
    TEST_CASE_PASSED;
  }

  TEST_CASE("b_counter_remove");

  ec = b_counter_remove(key2, &counter);
  if (ec != B_EC_SUCCESS) {
    TEST_CASE_FAILED("Exit code: %d", ec);
  }
  else {
    TEST_CASE_PASSED;
  }

  TEST_CASE("b_counter_count");

  count = b_counter_count(key2, &counter, NULL);
  if (count != 1) {
    TEST_CASE_FAILED("Expected 1 got %d", count);
  }
  else {
    TEST_CASE_PASSED;
  }
  
  TEST_CASE("b_counter_remove");

  ec = b_counter_remove(key2, &counter);
  if (ec != B_EC_SUCCESS) {
    TEST_CASE_FAILED("Exit code: %d", ec);
  }
  else {
    TEST_CASE_PASSED;
  }

  TEST_CASE("b_counter_count");

  count = b_counter_count(key2, &counter, NULL);
  if (count != 0) {
    TEST_CASE_FAILED("Expected 1 got %d", count);
  }
  else {
    TEST_CASE_PASSED;
  }

  TEST_CASE("b_counter_remove");

  ec = b_counter_remove(key2, &counter);
  if (ec != B_EC_SUCCESS) {
    TEST_CASE_FAILED("Exit code: %d", ec);
  }
  else {
    TEST_CASE_PASSED;
  }

  TEST_CASE("b_counter_add");

  int failed = 0;
  for (int i=0; i<10; i++) {
    ec = b_counter_add(key2, &counter);
    if (ec != B_EC_SUCCESS) {
      TEST_CASE_FAILED("Exit code: %d", ec);
      failed = 1;
      break;
    }
  }

  if (!failed) {
    TEST_CASE_PASSED;
  }

  TEST_CASE("b_counter_remove");

  failed = 0;
  for (int i=0; i<5; i++) {
    ec = b_counter_remove(key2, &counter);
    if (ec != B_EC_SUCCESS) {
      TEST_CASE_FAILED("Exit code: %d", ec);
      failed = 1;
      break;
    }
  }

  if (!failed) {
    TEST_CASE_PASSED;
  }

  TEST_CASE("b_counter_count");

  count = b_counter_count(key2, &counter, NULL);
  if (count != 5) {
    TEST_CASE_FAILED("Expected 5 got %d", count);
  }
  else {
    TEST_CASE_PASSED;
  }

  TEST_CASE("b_counter_free");

  ec = b_counter_free(&counter);
  if (ec != B_EC_SUCCESS) {
    TEST_CASE_FAILED("Exit code: %d", ec);
  }
  else {
    TEST_CASE_PASSED;
  }

  TEST_RESULT;
  return 0;
}
