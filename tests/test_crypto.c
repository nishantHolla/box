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

  uchar_t sha256[B_CRYPTO_SHA256_LENGTH] = {0};
  char sha256_hash[B_CRYPTO_SHA256_LENGTH * 2] = {0};

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

  TEST_OUTPUT("Exit code", "%d", ec);
  TEST_OUTPUT("Test string", "%s", test_string);
  TEST_OUTPUT("Expected SHA", "%s", expected_sha256);
  TEST_OUTPUT("Output SHA", "%s", sha256_hash);

  TEST_CASE("b_crypto_sha256_file");

  uchar_t sha256_file[B_CRYPTO_SHA256_LENGTH] = {0};
  char sha256_file_hash[B_CRYPTO_SHA256_LENGTH * 2] = {0};
  fprintf(test_file_write, "%s", test_string);
  fclose(test_file_write);

  ec = b_crypto_sha256_file(test_file_path, sha256_file);
  if (ec != B_EC_SUCCESS) {
    TEST_CASE_FAILED("Exit code: %d", ec);
  }

  for (int i=0; i<B_CRYPTO_SHA256_LENGTH; i++) {
    sprintf(&(sha256_file_hash[i*2]), "%02x", sha256_file[i]);
  }

  if (memcmp(sha256_file_hash, expected_sha256, strlen(expected_sha256))) {
    TEST_CASE_FAILED("Expected %s got %s", expected_sha256, sha256_file_hash);
  }
  else {
    TEST_CASE_PASSED;
  }

  TEST_OUTPUT("Exit code", "%d", ec);
  TEST_OUTPUT("Test string", "%s", test_string);
  TEST_OUTPUT("Expected SHA", "%s", expected_sha256);
  TEST_OUTPUT("Output SHA", "%s", sha256_file_hash);

  TEST_CASE("b_crypto_gen_cp");

  B_CRYPTO_PAIR cp;
  ec = b_crypto_gen_cp(password, strlen(password), &cp);
  if (ec != B_EC_SUCCESS) {
    TEST_CASE_FAILED("Exit code: %d", ec);
  }
  else {
    TEST_CASE_PASSED;
  }

  TEST_OUTPUT("Exit code", "%d", ec);
  TEST_OUTPUT("Password", "%s", password);
  TEST_OUTPUT("Key address: ", "%p", &(cp.key));
  TEST_OUTPUT("IV address: ", "%p", &(cp.iv));

  TEST_CASE("b_crypto_encode_string");

  char encode[100];
  size_t encode_len;

  char decode[100];
  size_t decode_len;

  ec = b_crypto_encode_string((const uchar_t *)test_string, strlen(test_string), encode, &encode_len);
  if (ec != B_EC_SUCCESS) {
    TEST_CASE_FAILED("Encode fail. Exit code: %d", ec);
  }

  ec = b_crypto_decode_string(encode, encode_len, (uchar_t *)decode, &decode_len);
  if (ec != B_EC_SUCCESS) {
    TEST_CASE_FAILED("Decode fail. Exit code: %d", ec);
  }

  if (strncmp(test_string, decode, decode_len) != 0) {
    TEST_CASE_FAILED("Expected %s got", test_string);
    for (int i=0; i<decode_len; i++) {
      putchar(decode[i]);
    }
    putchar('\n');
  }
  else {
    TEST_CASE_PASSED;
  }

  TEST_OUTPUT("Exit code", "%d", ec);
  TEST_OUTPUT("Test string", "%s", test_string);
  TEST_OUTPUT("Encoded string", "%.*s", (int)encode_len, encode);
  TEST_OUTPUT("Decoded string", "%.*s", (int)decode_len, decode);

  TEST_CASE("b_crypto_encrypt_string");

  uchar_t enc_string[100];
  char dec_string[100];
  size_t enc_string_length;
  size_t dec_string_length;

  ec = b_crypto_encrypt_string(test_string, strlen(test_string), enc_string, &enc_string_length, &cp);
  if (ec != B_EC_SUCCESS) {
    TEST_CASE_FAILED("Encrypt fail. Exit code: %d", ec);
  }

  ec = b_crypto_decrypt_string(enc_string, enc_string_length, dec_string, &dec_string_length, &cp);
  if (ec != B_EC_SUCCESS) {
    TEST_CASE_FAILED("Decrypt fail. Exit code: %d", ec);
  }
  else if (strncmp(test_string, dec_string, dec_string_length) != 0) {
    TEST_CASE_FAILED("Expected %s got %.*s", test_string, (int)dec_string_length, dec_string);
  }
  else {
    TEST_CASE_PASSED;
  }

  TEST_OUTPUT("Test string", "%s", test_string);
  TEST_OUTPUT("Encrypted", "%.*s", (int)enc_string_length, enc_string);
  TEST_OUTPUT("Decrypted", "%.*s", (int)dec_string_length, dec_string);

  TEST_CASE("b_crypto_encrypt_str");

  char enc_str[100];
  char dec_str[100];

  ec = b_crypto_encrypt_str(test_string, strlen(test_string), enc_str, &cp);
  if (ec != B_EC_SUCCESS) {
    TEST_CASE_FAILED("Encrypt fail. Exit code: %d", ec);
  }

  ec = b_crypto_decrypt_str(enc_str, strlen(enc_str), dec_str, &cp);
  if (ec != B_EC_SUCCESS) {
    TEST_CASE_FAILED("Decrypt fail. Exit code: %d", ec);
  }
  else if (strncmp(test_string, dec_str, strlen(dec_str)) != 0) {
    TEST_CASE_FAILED("Expected %s got %.*s", test_string, (int)strlen(dec_str), dec_str);
  }
  else {
    TEST_CASE_PASSED;
  }

  TEST_OUTPUT("Test string", "%s", test_string);
  TEST_OUTPUT("Encrypted", "%.*s", (int)strlen(enc_str), enc_str);
  TEST_OUTPUT("Decrypted", "%.*s", (int)strlen(dec_str), dec_str);

  TEST_CASE("b_crypto_encrypt_file");

  ec = b_crypto_encrypt_file(test_file_path, enc_file_path, &cp);
  if (ec != B_EC_SUCCESS) {
    TEST_CASE_FAILED("Exit code: %d", ec);
  }
  else {
    TEST_CASE_PASSED;
  }

  TEST_OUTPUT("Exit code", "%d", ec);

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
  uchar_t test_buffer[1000] = {0};
  const int br = fread(test_buffer, 1, 1000, test_file_read);

  FILE *dec_file = fopen(dec_file_path, "rb");
  if (!dec_file) {
    fclose(test_file_read);
    printf("Error: Could not read dec file.\n");
    exit(1);
  }
  uchar_t dec_buffer[1000] = {0};
  fread(dec_buffer, 1, 1000, dec_file);

  if (memcmp(test_buffer, dec_buffer, br)) {
    TEST_CASE_FAILED("Decrypted file does not match initial file");
  }
  else {
    TEST_CASE_PASSED;
  }

  TEST_OUTPUT("Exit code", "%d", ec);

  fclose(test_file_read);
  fclose(dec_file);
  remove(test_file_path);
  remove(enc_file_path);
  remove(dec_file_path);

  TEST_RESULT;
  return 0;
}
