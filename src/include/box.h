#ifndef BOX_H_
#define BOX_H_

#include <openssl/sha.h>
#include <stdint.h>

#define B_VERSION "0.1"

#define FNV_OFFSET 14695981039346656037UL
#define FNV_PRIME 1099511628211UL

#define B_COUNTER_KEY_LENGTH SHA256_DIGEST_LENGTH
#define B_COUNTER_CAPACITY 1000

typedef unsigned char uchar_t;

// Exit codes

typedef enum B_EXIT_CODE {
  B_EC_SUCCESS,
  B_EC_INVALID_ARG,
  B_EC_MALLOC_FAILED
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

#endif // !BOX_H_
