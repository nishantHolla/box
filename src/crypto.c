#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string.h>
#include "box.h"

B_EXIT_CODE b_crypto_sha256_string(const char *in, const size_t length, uchar_t *out) {
  if (!SHA256((const uchar_t *)in, length, out)) {
    return B_EC_SHA256_FAILED;
  }

  return B_EC_SUCCESS;
}

B_EXIT_CODE b_crypto_sha256_file(const char *in_path, uchar_t *out) {
  FILE *in_file = fopen(in_path, "rb");

  if (!in_file) {
    return B_EC_FILE_OPEN_FAILED;
  }

  fclose(in_file);
  return B_EC_SUCCESS;
}

B_EXIT_CODE b_crypto_gen_cp(const char *initializer, const size_t length, B_CRYPTO_PAIR *cp) {
  uchar_t sha256[B_CRYPTO_SHA256_LENGTH] = {0};

  if (b_crypto_sha256_string(initializer, length, sha256) == B_EC_SHA256_FAILED) {
    return B_EC_SHA256_FAILED;
  }

  memcpy(cp->key, sha256, B_CRYPTO_KEY_LENGTH);
  memcpy(cp->iv, sha256, B_CRYPTO_IV_LENGTH);

  return B_EC_SUCCESS;
}

B_EXIT_CODE b_crypto_encrypt_file(const char *in_path, const char *out_path, B_CRYPTO_PAIR *cp) {
  FILE *in_file = fopen(in_path, "rb");
  if (!in_file) {
    return B_EC_FILE_OPEN_FAILED;
  }

  // TODO: check if out_path exists

  FILE *out_file = fopen(out_path, "wb");
  if (!out_file) {
    b_crypto_file_cleanup(NULL, in_file, NULL);
    return B_EC_FILE_OPEN_FAILED;
  }

  EVP_CIPHER_CTX *ctx = NULL;
  int length = 0;

  if (!(ctx = EVP_CIPHER_CTX_new())) {
    b_crypto_file_cleanup(NULL, in_file, out_file);
    return B_EC_CRYPTO_CTX_FAILED;
  }

  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, cp->key, cp->iv)) {
    b_crypto_file_cleanup(ctx, in_file, out_file);
    return B_EC_CRYPTO_INIT_FAILED;
  }

  size_t bytes_read = 0;
  uchar_t buffer[B_CRYPTO_BUFFER_SIZE] = {0};
  uchar_t encrypted_buffer[B_CRYPTO_BUFFER_SIZE * 2] = {0};

  while ( (bytes_read = fread(buffer, 1, B_CRYPTO_BUFFER_SIZE, in_file)) > 0 ) {
    if (1 != EVP_EncryptUpdate(ctx, encrypted_buffer, &length, buffer, bytes_read)) {
      b_crypto_file_cleanup(ctx, in_file, out_file);
      return B_EC_CRYPTO_UPDATE_FAILED;
    }

    fwrite(encrypted_buffer, 1, length, out_file);
  }

  if (1 != EVP_EncryptFinal_ex(ctx, encrypted_buffer, &length)) {
    b_crypto_file_cleanup(ctx, in_file, out_file);
    return B_EC_CRYPTO_FINAL_FAILED;
  }
  fwrite(encrypted_buffer, 1, length, out_file);

  b_crypto_file_cleanup(ctx, in_file, out_file);
  return B_EC_SUCCESS;
}

B_EXIT_CODE b_crypto_decrypt_file(const char *in_path, const char *out_path, B_CRYPTO_PAIR *cp) {
  FILE *in_file = fopen(in_path, "rb");
  if (!in_file) {
    return B_EC_FILE_OPEN_FAILED;
  }

  // TODO: check if out_path exists

  FILE *out_file = fopen(out_path, "wb");
  if (!out_file) {
    b_crypto_file_cleanup(NULL, in_file, NULL);
    return B_EC_FILE_OPEN_FAILED;
  }

  EVP_CIPHER_CTX *ctx = NULL;
  int length = 0;

  if (!(ctx = EVP_CIPHER_CTX_new())) {
    b_crypto_file_cleanup(ctx, in_file, out_file);
    return B_EC_CRYPTO_CTX_FAILED;
  }

  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, cp->key, cp->iv)) {
    b_crypto_file_cleanup(ctx, in_file, out_file);
    return B_EC_CRYPTO_INIT_FAILED;
  }

  size_t bytes_read = 0;
  uchar_t buffer[B_CRYPTO_BUFFER_SIZE] = {0};
  uchar_t decrypted_buffer[B_CRYPTO_BUFFER_SIZE * 2] = {0};

  while ( (bytes_read = fread(buffer, 1, B_CRYPTO_BUFFER_SIZE, in_file)) > 0 ) {
    if (1 != EVP_DecryptUpdate(ctx, decrypted_buffer, &length, buffer, bytes_read)) {
      b_crypto_file_cleanup(ctx, in_file, out_file);
      return B_EC_CRYPTO_UPDATE_FAILED;
    }

    fwrite(decrypted_buffer, 1, length, out_file);
  }

  if (1 != EVP_DecryptFinal_ex(ctx, decrypted_buffer, &length)) {
    b_crypto_file_cleanup(ctx, in_file, out_file);
    return B_EC_CRYPTO_FINAL_FAILED;
  }
  fwrite(decrypted_buffer, 1, length, out_file);

  b_crypto_file_cleanup(ctx, in_file, out_file);
  return B_EC_SUCCESS;
}

void b_crypto_file_cleanup(EVP_CIPHER_CTX *ctx, FILE *in_file, FILE *out_file) {
  if (ctx) {
    EVP_CIPHER_CTX_free(ctx);
  }

  if (in_file) {
    fclose(in_file);
  }

  if (out_file) {
    fclose(out_file);
  }
}
