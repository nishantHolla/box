#include <string.h>
#include <stdio.h>
#include "box.h"

B_EXIT_CODE b_box_init(const char root_path[B_PATH_MAX_LENGTH], B_BOX *box) {
  box->is_valid = 0;
  b_counter_init(&(box->enc_file_hash_counter));

  if (b_path_stat(root_path) != B_PATH_DIR) {
    return B_EC_INVALID_ARG;
  }

  b_path_abs(root_path, box->root_path);
  char box_desc_path[B_PATH_MAX_LENGTH];
  b_path_concat(box->root_path, B_BOX_DESC_FILE, box_desc_path);

  if (b_path_stat(box_desc_path) != B_PATH_FILE) {
    return B_EC_SUCCESS;
  }
  else {
    box->is_valid = 1;
  }

  FILE *box_desc_file = fopen(box_desc_path, "r");
  if (!box_desc_file) {
    return B_EC_FILE_OPEN_FAILED;
  }

  if (!fgets(box->name, B_BOX_MAX_NAME_LENGTH, box_desc_file)) {
    fclose(box_desc_file);
    return B_EC_BOX_INIT_FAILED;
  }
  box->name[strcspn(box->name, "\n")] = '\0';

  char box_password_hash_hex[B_CRYPTO_SHA256_LENGTH * 2];
  if (!fgets(box_password_hash_hex, B_CRYPTO_SHA256_LENGTH * 2 + 1, box_desc_file)) {
    fclose(box_desc_file);
    return B_EC_BOX_INIT_FAILED;
  }

  size_t out_length = 0;
  box_password_hash_hex[strcspn(box_password_hash_hex, "\n")] = 0;
  b_crypto_decode_string(
    box_password_hash_hex,
    strnlen(box_password_hash_hex, B_CRYPTO_SHA256_LENGTH * 2),
    box->password_hash,
    &out_length
  );

  char line[B_BOX_MAX_LINE_LENGTH];
  while (fgets(line, B_BOX_MAX_LINE_LENGTH + 1, box_desc_file)) {
    line[strcspn(line, "\n")] = 0;

    if (strnlen(line, B_BOX_MAX_LINE_LENGTH) < B_CRYPTO_SHA256_LENGTH) {
      continue;
    }

    char line_hex[B_CRYPTO_SHA256_LENGTH * 2];
    int count;
    sscanf(line, "%s %d", line_hex, &count);

    uchar_t hash[B_CRYPTO_SHA256_LENGTH];
    size_t out_len;
    b_crypto_decode_string(line_hex, strnlen(line_hex, B_BOX_MAX_LINE_LENGTH + 1), hash, &out_len);

    for (int i=0; i<count; i++) {
      b_counter_add(hash, &(box->enc_file_hash_counter));
    }

  }


  fclose(box_desc_file);
  return B_EC_SUCCESS;
}

B_EXIT_CODE b_box_free(B_BOX *box) {
  if (box->is_valid) {
    B_EXIT_CODE ec;
    char box_desc_file_path[B_PATH_MAX_LENGTH];

    ec = b_path_concat(box->root_path, B_BOX_DESC_FILE, box_desc_file_path);
    if (ec != B_EC_SUCCESS) {
      return B_EC_BOX_FREE_FAILED;
    }

    FILE *box_desc_file = fopen(box_desc_file_path, "w");
    if (!box_desc_file) {
      return B_EC_BOX_FREE_FAILED;
    }

    size_t out_len = 0;
    char hash_hex[B_CRYPTO_SHA256_LENGTH * 2 + 1];
    b_crypto_encode_string(box->password_hash, B_CRYPTO_SHA256_LENGTH, hash_hex, &out_len);

    fprintf(box_desc_file, "%s\n%s\n", box->name, hash_hex);

    for (int i=0; i<B_COUNTER_CAPACITY; i++) {
      B_COUNTER_BUCKET *b = box->enc_file_hash_counter.buffer[i];
      while (b) {
        b_crypto_encode_string(b->key, B_CRYPTO_SHA256_LENGTH, hash_hex, &out_len);
        fprintf(box_desc_file, "%s %d\n", hash_hex, b->count);
        b = b->next;
      }
    }

    fclose(box_desc_file);
  }
  box->is_valid = 0;
  b_counter_free(&(box->enc_file_hash_counter));

  return B_EC_SUCCESS;
}
