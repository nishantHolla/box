#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "box.h"
#include "test.h"

int test_case_passed = 0;
int test_case_length = 0;

const char *test_string = "The quick brown fox jumped over the lazy dog.";
const char *expected_sha256 = "68b1282b91de2c054c36629cb8dd447f12f096d3e3c587978dc2248444633483";
const char *test_file_path = "test_file.txt";
const char *enc_file_path = "test_enc_file.txt";
const char *dec_file_path = "test_dec_file.txt";
const char *password = "hello, world";

int main(void) {
  B_EXIT_CODE ec;

  FILE *test_file_write = fopen(test_file_path, "w");
  if (!test_file_write) {
    printf("Error: Could not create test file.\n");
    exit(1);
  }

  TEST_CASE("b_crypto_sha256_string");

  uchar_t sha256[B_CRYPTO_SHA256_LENGTH];
  char sha256_hash[B_CRYPTO_SHA256_LENGTH * 2];

  ec = b_crypto_sha256_string(test_string, strlen(test_string), sha256);
  if (ec != B_EC_SUCCESS) {
    TEST_CASE_FAILED("Exit code: %d", ec);
  }

  for (int i=0; i<B_CRYPTO_SHA256_LENGTH; i++) {
    sprintf(&(sha256_hash[i*2]), "%02x", sha256[i]);
  }

  if (memcmp(sha256_hash, expected_sha256, strlen(expected_sha256))) {
    TEST_CASE_FAILED("Expected %s got %s", expected_sha256, sha256_hash);
  }
  else {
    TEST_CASE_PASSED;
  }

  TEST_CASE("b_crypto_sha256_file");

  fprintf(test_file_write, "%s", test_string);
  ec = b_crypto_sha256_file(test_file_path, sha256);
  if (ec != B_EC_SUCCESS) {
    TEST_CASE_FAILED("Exit code: %d", ec);
  }

  for (int i=0; i<B_CRYPTO_SHA256_LENGTH; i++) {
    sprintf(&(sha256_hash[i*2]), "%02x", sha256[i]);
  }

  if (memcmp(sha256_hash, expected_sha256, strlen(expected_sha256))) {
    TEST_CASE_FAILED("Expected %s got %s", expected_sha256, sha256_hash);
  }
  else {
    TEST_CASE_PASSED;
  }
  fclose(test_file_write);

  TEST_CASE("b_crypto_gen_cp");

  B_CRYPTO_PAIR cp;
  ec = b_crypto_gen_cp(password, strlen(password), &cp);
  if (ec != B_EC_SUCCESS) {
    TEST_CASE_FAILED("Exit code: %d", ec);
  }
  else {
    TEST_CASE_PASSED;
  }

  TEST_CASE("b_crypto_encrypt_file");

  ec = b_crypto_encrypt_file(test_file_path, enc_file_path, &cp);
  if (ec != B_EC_SUCCESS) {
    TEST_CASE_FAILED("Exit code: %d", ec);
  }
  else {
    TEST_CASE_PASSED;
  }

  TEST_CASE("b_crypto_decrypt_file");

  ec = b_crypto_decrypt_file(enc_file_path, dec_file_path, &cp);
  if (ec != B_EC_SUCCESS) {
    TEST_CASE_FAILED("Exit code: %d", ec);
  }

  FILE *test_file_read = fopen(test_file_path, "rb");
  if (!test_file_read) {
    printf("Error: Could not read enc file.\n");
    exit(1);
  }
  uchar_t test_buffer[1000];
  const int br = fread(test_buffer, 1, 1000, test_file_read);

  FILE *dec_file = fopen(dec_file_path, "rb");
  if (!dec_file) {
    fclose(test_file_read);
    printf("Error: Could not read dec file.\n");
    exit(1);
  }
  uchar_t dec_buffer[1000];
  fread(dec_buffer, 1, 1000, dec_file);

  if (memcmp(test_buffer, dec_buffer, br)) {
    TEST_CASE_FAILED("Decrypted file does not match initial file");
  }
  else {
    TEST_CASE_PASSED;
  }

  fclose(test_file_read);
  fclose(dec_file);
  remove(test_file_path);
  remove(enc_file_path);
  remove(dec_file_path);
  TEST_RESULT;
  return 0;
}
