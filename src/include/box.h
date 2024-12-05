#ifndef BOX_H_
#define BOX_H_

#define _XOPEN_SOURCE 700
#define __USE_XOPEN_EXTENDED

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <ftw.h>

#define B_VERSION "0.1"

#define B_PATH_MAX_LENGTH 1024

#define FNV_OFFSET 14695981039346656037UL
#define FNV_PRIME 1099511628211UL

#define B_COUNTER_CAPACITY 1000
#define B_COUNTER_KEY_LENGTH SHA256_DIGEST_LENGTH

#define B_CRYPTO_KEY_LENGTH SHA256_DIGEST_LENGTH
#define B_CRYPTO_IV_LENGTH SHA256_DIGEST_LENGTH / 2
#define B_CRYPTO_SHA256_LENGTH SHA256_DIGEST_LENGTH
#define B_CRYPTO_BUFFER_SIZE 4096

#define B_BOX_MAX_NAME_LENGTH 100
#define B_BOX_MAX_PASSWORD_LENGTH 100
#define B_BOX_MAX_FILE_NAME_LENGTH 100
#define B_BOX_MAX_LINE_LENGTH B_CRYPTO_SHA256_LENGTH * 2 + 10
#define B_BOX_DESC_FILE "box_desc.txt"

typedef unsigned char uchar_t;

// Exit codes

typedef enum B_EXIT_CODE {
  B_EC_SUCCESS,
  B_EC_INVALID_ARG,
  B_EC_MALLOC_FAILED,
  B_EC_SHA256_FAILED,
  B_EC_FILE_OPEN_FAILED,
  B_EC_CRYPTO_CTX_FAILED,
  B_EC_CRYPTO_INIT_FAILED,
  B_EC_CRYPTO_UPDATE_FAILED,
  B_EC_CRYPTO_FINAL_FAILED,
  B_EC_BOX_INIT_FAILED,
  B_EC_BOX_FREE_FAILED,
  B_EC_PATH_NOT_FOUND,
  B_EC_IO_INPUT_FAILED,
  B_EC_BOX_EXISTS,
  B_EC_BOX_DOES_NOT_EXIST,
  B_EC_AUTH_FAILED
} B_EXIT_CODE;

// Path

typedef enum B_PATH_STAT {
  B_PATH_DIR,
  B_PATH_FILE,
  B_PATH_LINK_DIR,
  B_PATH_LINK_FILE,
  B_PATH_UNKNOWN,
  B_PATH_ERROR
} B_PATH_STAT;

B_EXIT_CODE b_path_abs(const char *in, char *out);
B_PATH_STAT b_path_stat(const char *path);
B_EXIT_CODE b_path_concat(const char *left, const char *right, char *out);
B_EXIT_CODE b_path_parent(const char *in, char *out);

// Counter

typedef struct B_COUNTER_BUCKET {
  uchar_t key[B_COUNTER_KEY_LENGTH];
  uint16_t count;
  struct B_COUNTER_BUCKET *next;
} B_COUNTER_BUCKET;

typedef struct B_COUNTER {
  B_COUNTER_BUCKET *buffer[B_COUNTER_CAPACITY];
  uint16_t size;
} B_COUNTER;

B_COUNTER_BUCKET *b_counter_create_bucket(const uchar_t *key);
uint64_t b_counter_hash(const uchar_t *key);
uint64_t b_counter_count(const uchar_t *key, B_COUNTER *counter, B_COUNTER_BUCKET **result);

B_EXIT_CODE b_counter_init(B_COUNTER *counter);
B_EXIT_CODE b_counter_add(const uchar_t *key, B_COUNTER *counter);
B_EXIT_CODE b_counter_remove(const uchar_t *key, B_COUNTER *counter);
B_EXIT_CODE b_counter_free(B_COUNTER *counter);

// Crypto

typedef struct B_CRYPTO_PAIR {
  uchar_t key[B_CRYPTO_KEY_LENGTH];
  uchar_t iv[B_CRYPTO_IV_LENGTH];
} B_CRYPTO_PAIR;

B_EXIT_CODE b_crypto_sha256_string(const char *in, const size_t length, uchar_t *out);
B_EXIT_CODE b_crypto_sha256_file(const char *in_path, uchar_t *out);

B_EXIT_CODE b_crypto_gen_cp(const char *initializer, const size_t length, B_CRYPTO_PAIR *cp);

B_EXIT_CODE b_crypto_encode_string(
  const uchar_t *in, const size_t length, char *out, size_t *out_length
);
B_EXIT_CODE b_crypto_decode_string(
  char *in, const size_t length, uchar_t *out, size_t *out_length
);
int hex_to_dec(const char x);

B_EXIT_CODE b_crypto_encrypt_string(
  const char *in, const size_t length, uchar_t *out, size_t *out_length, B_CRYPTO_PAIR *cp
);
B_EXIT_CODE b_crypto_decrypt_string(
  const uchar_t *in, const size_t length, char *out, size_t *out_length, B_CRYPTO_PAIR *cp
);

B_EXIT_CODE b_crypto_encrypt_str(const char *in, size_t length, char *out, B_CRYPTO_PAIR *cp);
B_EXIT_CODE b_crypto_decrypt_str(const char *in, size_t length, char *out, B_CRYPTO_PAIR *cp);

B_EXIT_CODE b_crypto_encrypt_file(const char *in_path, const char *out_path, B_CRYPTO_PAIR *cp);
B_EXIT_CODE b_crypto_decrypt_file(const char *in_path, const char *out_path, B_CRYPTO_PAIR *cp);

void b_crypto_cipher_cleanup(EVP_CIPHER_CTX *ctx, FILE *in_file, FILE *out_file);
void b_crypto_sha_cleanup(EVP_MD_CTX *ctx, FILE *in_file, FILE *out_file);

// Box

typedef struct B_BOX {
  int is_valid;
  char root_path[B_PATH_MAX_LENGTH];
  char name[B_BOX_MAX_NAME_LENGTH];
  uchar_t password_hash[B_CRYPTO_SHA256_LENGTH];
  B_CRYPTO_PAIR cp;
  B_COUNTER enc_file_hash_counter;
} B_BOX;

B_EXIT_CODE b_box_init(const char *root_path, B_BOX *box);
B_EXIT_CODE b_box_free(B_BOX *box);
int b_box_check_descendants_helper(const char *fpath, const struct stat *sb,
          int typeflag, struct FTW *ftwbuf);
B_EXIT_CODE b_box_check_descendants(const char *root_path, char *result);
B_EXIT_CODE b_box_check_ancestors(const char *root_path, char *result);
B_EXIT_CODE b_box_create(B_BOX *box);
int b_box_wrap_helper(const char *fpath, const struct stat *sb,
          int typeflag, struct FTW *ftwbuf);
B_EXIT_CODE b_box_wrap(B_BOX *box);
int b_box_unwrap_helper(const char *fpath, const struct stat *sb,
          int typeflag, struct FTW *ftwbuf);
B_EXIT_CODE b_box_unwrap(B_BOX *box);
B_EXIT_CODE b_box_authenticate(B_BOX *box);

#endif // !BOX_H_
