#define _XOPEN_SOURCE 500

#ifndef USE_FDS
#define USE_FDS 15
#endif

#include <ftw.h>
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <libgen.h>
#include "box.h"

static char descendants_path[B_PATH_MAX_LENGTH];

B_EXIT_CODE b_box_init(const char *root_path, B_BOX *box) {
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

  char box_password_hash_hex[B_CRYPTO_SHA256_LENGTH * 2 + 1];
  if (!fgets(box_password_hash_hex, B_CRYPTO_SHA256_LENGTH * 2 + 1, box_desc_file)) {
    fclose(box_desc_file);
    return B_EC_BOX_INIT_FAILED;
  }

  size_t out_length = 0;
  box_password_hash_hex[strcspn(box_password_hash_hex, "\n")] = 0;
  b_crypto_decode_string(
    box_password_hash_hex,
    strlen(box_password_hash_hex),
    box->password_hash,
    &out_length
  );

  char line[B_BOX_MAX_LINE_LENGTH + 1];
  while (fgets(line, B_BOX_MAX_LINE_LENGTH + 1, box_desc_file)) {
    line[strcspn(line, "\n")] = 0;

    if (strlen(line) < B_CRYPTO_SHA256_LENGTH) {
      continue;
    }

    char line_hex[B_CRYPTO_SHA256_LENGTH * 2];
    int count;
    sscanf(line, "%s %d", line_hex, &count);

    uchar_t hash[B_CRYPTO_SHA256_LENGTH];
    size_t out_len;
    b_crypto_decode_string(line_hex, strlen(line_hex), hash, &out_len);

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

int b_box_check_descendants_helper(const char *fpath, const struct stat *sb,
          int typeflag, struct FTW *ftwbuf) {
  if (typeflag != FTW_F) {
    return 0;
  }

  char pathname[B_PATH_MAX_LENGTH];
  strncpy(pathname, fpath, B_PATH_MAX_LENGTH);
  char *filename = basename(pathname);

  if (strncmp(filename, B_BOX_DESC_FILE, 15) == 0) {
    char parentpath[B_PATH_MAX_LENGTH];

    if (b_path_parent(fpath, parentpath) != B_EC_SUCCESS) {
      return 1;
    }

    strncpy(descendants_path, parentpath, B_PATH_MAX_LENGTH);
    return 1;
  }

  return 0;
}

B_EXIT_CODE b_box_check_descendants(const char *root_path, char *result) {
  if (result) {
    strcpy(result, "");
  }

  char abs_path[B_PATH_MAX_LENGTH];
  if (b_path_abs(root_path, abs_path) != B_EC_SUCCESS) {
    return B_EC_INVALID_ARG;
  }

  const int r = nftw(abs_path, &b_box_check_descendants_helper, USE_FDS, FTW_PHYS);

  if (r == 1) {
    strncpy(result, descendants_path, B_PATH_MAX_LENGTH);
    return B_EC_SUCCESS;
  }
  else {
    return B_EC_PATH_NOT_FOUND;
  }
}

B_EXIT_CODE b_box_check_ancestors(const char *root_path, char *result) {
  char abs_path[B_PATH_MAX_LENGTH];
  if (b_path_abs(root_path, abs_path) != B_EC_SUCCESS) {
    return B_EC_INVALID_ARG;
  }

  char current[B_PATH_MAX_LENGTH];
  strncpy(current, abs_path, B_PATH_MAX_LENGTH);

  while (strncmp(current, "/home", B_PATH_MAX_LENGTH) != 0) {
    char check[B_PATH_MAX_LENGTH];
    if (b_path_concat(current, B_BOX_DESC_FILE, check) != B_EC_SUCCESS) {
      return B_EC_INVALID_ARG;
    }

    if (b_path_stat(check) == B_PATH_FILE) {
      if (result) {
        strncpy(result, current, B_PATH_MAX_LENGTH);
      }
      return B_EC_SUCCESS;
    }

    if (b_path_parent(current, current) != B_EC_SUCCESS) {
      return B_EC_INVALID_ARG;
    }
  }

  if (result) {
    strcpy(result, "");
  }

  return B_EC_PATH_NOT_FOUND;
}

B_EXIT_CODE b_box_create(B_BOX *box) {
  B_EXIT_CODE ec;
  if (box->is_valid) {
    return B_EC_BOX_EXISTS;
  }

  if (b_path_stat(box->root_path) != B_PATH_DIR) {
    return B_EC_INVALID_ARG;
  }

  char check_result[B_PATH_MAX_LENGTH];
  if (
    b_box_check_descendants(box->root_path, check_result) != B_EC_PATH_NOT_FOUND ||
    b_box_check_ancestors(box->root_path, check_result) != B_EC_PATH_NOT_FOUND
  ) {
    printf("Error: Box already exists at path %s. You can not nest boxes!\n", check_result);
    return B_EC_BOX_EXISTS;
  }

  printf("Enter box name: ");
  if (fgets(box->name, B_BOX_MAX_NAME_LENGTH, stdin) != NULL) {
    box->name[strcspn(box->name, "\n")] = '\0';
  }
  else {
    return B_EC_IO_INPUT_FAILED;
  }

  printf("Enter box password: ");
  char password[B_BOX_MAX_PASSWORD_LENGTH];
  if (fgets(password, B_BOX_MAX_PASSWORD_LENGTH, stdin) != NULL) {
    password[strcspn(password, "\n")] = '\0';
    ec = b_crypto_sha256_string(password, strlen(password), box->password_hash);
    if (ec != B_EC_SUCCESS) {
      return B_EC_SHA256_FAILED;
    }
  }
  else {
    return B_EC_IO_INPUT_FAILED;
  }

  box->is_valid = 1;
  return B_EC_SUCCESS;
}
