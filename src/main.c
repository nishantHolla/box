#include <openssl/sha.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "box.h"

int main(void) {
  printf("Box v%s\n", B_VERSION);
  printf("Hello, World.\n");

  B_BOX box;
  B_EXIT_CODE ec = b_box_init("./dir", &box);

  printf("EC: %d\n", ec);
  printf("Is valid: %d\n", box.is_valid);
  printf("Root path: %s\n", box.root_path);
  printf("Name: %s\n", box.name);
  char password_hex[B_CRYPTO_SHA256_LENGTH * 2];
  size_t out_len;
  b_crypto_encode_string(box.password_hash, B_CRYPTO_SHA256_LENGTH, password_hex, &out_len);
  printf("Password hex: %s\n", password_hex);

  char hash_hex[] = "5841b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03";
  uchar_t hash[B_CRYPTO_SHA256_LENGTH];
  b_crypto_decode_string(hash_hex, strlen(hash_hex), hash, &out_len);

  const uint64_t count = b_counter_count(hash, &box.enc_file_hash_counter, NULL);
  printf("Count: %lu", count);

  b_box_free(&box);
  return 0;
}
