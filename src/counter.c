#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "box.h"

B_EXIT_CODE b_counter_init(B_COUNTER *counter) {
  if (!counter) {
    return B_EC_INVALID_ARG;
  }

  counter->size = 0;
  for (int i = 0; i < B_COUNTER_CAPACITY; i++) {
    counter->buffer[i] = NULL;
  }

  return B_EC_SUCCESS;
}

B_COUNTER_BUCKET *b_counter_create_bucket(const uchar_t *key) {
  B_COUNTER_BUCKET *new_bucket = (B_COUNTER_BUCKET *) malloc(sizeof(B_COUNTER_BUCKET));
  if (!new_bucket) {
    return NULL;
  }

  strncpy((char *)new_bucket->key, (const char *)key, B_COUNTER_KEY_LENGTH);
  new_bucket->next = NULL;
  new_bucket->count = 1;

  return new_bucket;
}

uint64_t b_counter_hash(const uchar_t *key) {
  uint64_t hash = FNV_OFFSET;

  for (int i = 0; i < B_COUNTER_KEY_LENGTH; i++) {
    hash ^= (uint64_t)(unsigned char)(key[i]);
    hash *= FNV_PRIME;
  }

  return hash;
}

uint64_t b_counter_count(const uchar_t *key, B_COUNTER *counter, B_COUNTER_BUCKET **result) {
  if (!counter) {
    return 0;
  }

  uint64_t index = b_counter_hash(key) % B_COUNTER_CAPACITY;
  B_COUNTER_BUCKET *traversal = counter->buffer[index];

  while (
    traversal &&
    strncmp((const char *)traversal->key, (const char *)key, B_COUNTER_KEY_LENGTH) != 0
  ) {
    traversal = traversal->next;
  }

  if (!traversal) {
    return 0;
  }

  if (result) {
    *result = traversal;
  }

  return traversal->count;
}

B_EXIT_CODE b_counter_add(const uchar_t *key, B_COUNTER *counter) {
  if (!counter) {
    return B_EC_INVALID_ARG;
  }

  B_COUNTER_BUCKET *test = NULL;
  if (b_counter_count(key, counter, &test) != 0) {
    test->count++;
  }
  else {
    uint64_t index = b_counter_hash(key) % B_COUNTER_CAPACITY;

    B_COUNTER_BUCKET *new_bucket = b_counter_create_bucket(key);
    if (!new_bucket) {
      return B_EC_MALLOC_FAILED;
    }

    new_bucket->next = counter->buffer[index];
    counter->buffer[index] = new_bucket;
  }

  counter->size++;
  return B_EC_SUCCESS;
}

B_EXIT_CODE b_counter_remove(const uchar_t *key, B_COUNTER *counter) {
  if (!counter) {
    return B_EC_INVALID_ARG;
  }

  B_COUNTER_BUCKET *test = NULL;
  if (b_counter_count(key, counter, &test) == 0 || test == NULL) {
    return B_EC_SUCCESS;
  }

  if (test->count != 0) {
    test->count--;
    return B_EC_SUCCESS;
  }

  uint64_t index = b_counter_hash(key) % B_COUNTER_CAPACITY;
  B_COUNTER_BUCKET *prev = NULL;
  B_COUNTER_BUCKET *traversal = counter->buffer[index];

  while (traversal != test) {
    prev = traversal;
    traversal = traversal->next;
  }

  if (!prev) {
    counter->buffer[index] = traversal->next;
  }
  else {
    prev->next = traversal->next;
  }
  free(traversal);

  counter->size--;
  return B_EC_SUCCESS;
}

B_EXIT_CODE b_counter_free(B_COUNTER *counter) {
  if (!counter) {
    return B_EC_INVALID_ARG;
  }

  counter->size = 0;
  for (int i = 0; i < B_COUNTER_CAPACITY; i++) {
    B_COUNTER_BUCKET *traversal = counter->buffer[i];

    while (traversal) {
      B_COUNTER_BUCKET *temp = traversal->next;
      free(traversal);
      traversal = temp;
    }

    counter->buffer[i] = NULL;
  }

  return B_EC_SUCCESS;
}
