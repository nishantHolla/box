#ifndef BOX_H_
#define BOX_H_

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdint.h>

#define B_VERSION "0.1"

#define FNV_OFFSET 14695981039346656037UL
#define FNV_PRIME 1099511628211UL

#define B_COUNTER_CAPACITY 1000
#define B_COUNTER_KEY_LENGTH SHA256_DIGEST_LENGTH

#define B_CRYPTO_KEY_LENGTH SHA256_DIGEST_LENGTH
#define B_CRYPTO_IV_LENGTH SHA256_DIGEST_LENGTH / 2
#define B_CRYPTO_SHA256_LENGTH SHA256_DIGEST_LENGTH
#define B_CRYPTO_BUFFER_SIZE 4096

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
  B_EC_CRYPTO_FINAL_FAILED
} B_EXIT_CODE;

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

B_EXIT_CODE b_crypto_encrypt_file(const char *in_path, const char *out_path, B_CRYPTO_PAIR *cp);
B_EXIT_CODE b_crypto_decrypt_file(const char *in_path, const char *out_path, B_CRYPTO_PAIR *cp);
void b_crypto_file_cleanup(EVP_CIPHER_CTX *ctx, FILE *in_file, FILE *out_file);

#endif // !BOX_H_
