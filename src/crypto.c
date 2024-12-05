#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <ctype.h>
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

  EVP_MD_CTX *ctx = NULL;

  if (!(ctx = EVP_MD_CTX_new())) {
    b_crypto_sha_cleanup(NULL, in_file, NULL);
    return B_EC_CRYPTO_CTX_FAILED;
  }

  if (1 != EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) {
    b_crypto_sha_cleanup(ctx, in_file, NULL);
    return B_EC_CRYPTO_INIT_FAILED;
  }

  size_t bytes_read = 0;
  uchar_t buffer[B_CRYPTO_BUFFER_SIZE] = {0};
  unsigned int length = 0;

  while ( (bytes_read = fread(buffer, 1, B_CRYPTO_BUFFER_SIZE, in_file)) > 0) {
    if (1 != EVP_DigestUpdate(ctx, buffer, bytes_read)) {
      b_crypto_sha_cleanup(ctx, in_file, NULL);
      return B_EC_CRYPTO_UPDATE_FAILED;
    }
  }

  if (1 != EVP_DigestFinal_ex(ctx, out, &length)) {
    b_crypto_sha_cleanup(ctx, in_file, NULL);
    return B_EC_CRYPTO_FINAL_FAILED;
  }

  b_crypto_sha_cleanup(ctx, in_file, NULL);
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

B_EXIT_CODE b_crypto_encode_string(
  const uchar_t *in, const size_t length, char *out, size_t *out_length
) {
  *out_length = 0;

  for (size_t i=0; i<length; i++) {
    snprintf(&(out[2*i]), 3, "%02x", in[i]);
    *out_length += 2;
  }

  return B_EC_SUCCESS;
}

int hex_to_dec(const char x) {
  if (isdigit(x)) {
    return x - '0';
  }

  char xl = tolower(x);

  if (xl >= 'a' && xl <= 'f') {
    return xl - 'a' + 10;
  }

  return -1;
}

B_EXIT_CODE b_crypto_decode_string(
  char *in, const size_t length, uchar_t *out, size_t *out_length
) {
  *out_length = 0;

  for (size_t i=0; i<length; i += 2) {
    int high = hex_to_dec(in[i]);
    int low = hex_to_dec(in[i+1]);

    if (high < 0 || low < 0) {
      return B_EC_INVALID_ARG;
    }

    out[i/2] = (high << 4) + low;
    *out_length += 1;
  }

  return B_EC_SUCCESS;
}

B_EXIT_CODE b_crypto_encrypt_string(
  const char *in, const size_t length, uchar_t *out, size_t *out_length, B_CRYPTO_PAIR *cp
) {
  *out_length = 0;

  EVP_CIPHER_CTX *ctx = NULL;
  int enc_length = 0;

  if (!(ctx = EVP_CIPHER_CTX_new())) {
    return B_EC_CRYPTO_CTX_FAILED;
  }

  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, cp->key, cp->iv)) {
    b_crypto_cipher_cleanup(ctx, NULL, NULL);
    return B_EC_CRYPTO_INIT_FAILED;
  }

  if (1 != EVP_EncryptUpdate(ctx, out, &enc_length, (const uchar_t *)in, length)) {
    b_crypto_cipher_cleanup(ctx, NULL, NULL);
    return B_EC_CRYPTO_UPDATE_FAILED;
  }
  *out_length += enc_length;

  if (1 != EVP_EncryptFinal_ex(ctx, out + enc_length, &enc_length)) {
    b_crypto_cipher_cleanup(ctx, NULL, NULL);
    return B_EC_CRYPTO_FINAL_FAILED;
  }
  *out_length += enc_length;

  b_crypto_cipher_cleanup(ctx, NULL, NULL);
  return B_EC_SUCCESS;
}

B_EXIT_CODE b_crypto_decrypt_string(
  const uchar_t *in, const size_t length, char *out, size_t *out_length, B_CRYPTO_PAIR *cp
) {
  *out_length = 0;

  EVP_CIPHER_CTX *ctx = NULL;
  int dec_length = 0;

  if (!(ctx = EVP_CIPHER_CTX_new())) {
    return B_EC_CRYPTO_CTX_FAILED;
  }

  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, cp->key, cp->iv)) {
    b_crypto_cipher_cleanup(ctx, NULL, NULL);
    return B_EC_CRYPTO_INIT_FAILED;
  }

  if (1 != EVP_DecryptUpdate(ctx, (uchar_t *)out, &dec_length, in, length)) {
    b_crypto_cipher_cleanup(ctx, NULL, NULL);
    return B_EC_CRYPTO_UPDATE_FAILED;
  }
  *out_length += dec_length;

  if (1 != EVP_DecryptFinal_ex(ctx, (uchar_t *)(out + dec_length), &dec_length)) {
    b_crypto_cipher_cleanup(ctx, NULL, NULL);
    return B_EC_CRYPTO_FINAL_FAILED;
  }
  *out_length += dec_length;

  b_crypto_cipher_cleanup(ctx, NULL, NULL);
  return B_EC_SUCCESS;
}

B_EXIT_CODE b_crypto_encrypt_str(const char *in, size_t length, char *out, B_CRYPTO_PAIR *cp) {
  int key = 0;
  for (int i = 0; i < B_CRYPTO_KEY_LENGTH; i++) {
    key += cp->key[i];
  }

  key = key % 26;

  for (int i = 0; i < length; i++) {
    if (in[i] >= 'a' && in[i] <= 'z') {
      out[i] = (in[i] + key - 'a') % 26 + 'a';
    }
    else if (in[i] >= 'A' && in[i] <= 'Z') {
      out[i] = (in[i] + key - 'A') % 26 + 'A';
    }
    else {
      out[i] = in[i];
    }
  }

  out[length] = 0;
  return B_EC_SUCCESS;
}

B_EXIT_CODE b_crypto_decrypt_str(const char *in, size_t length, char *out, B_CRYPTO_PAIR *cp) {
  int key = 0;
  for (int i = 0; i < B_CRYPTO_KEY_LENGTH; i++) {
    key += cp->key[i];
  }

  key = 26 - (key % 26);

  for (int i = 0; i < length; i++) {
    if (in[i] >= 'a' && in[i] <= 'z') {
      out[i] = (in[i] + key - 'a') % 26 + 'a';
    }
    else if (in[i] >= 'A' && in[i] <= 'Z') {
      out[i] = (in[i] + key - 'A') % 26 + 'A';
    }
    else if (in[i] >= '0' && in[i] <= '9') {
      out[i] = (in[i] + key - '0') % 10 + '0';
    }
    else {
      out[i] = in[i];
    }
  }

  out[length] = 0;
  return B_EC_SUCCESS;

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
    b_crypto_cipher_cleanup(NULL, in_file, NULL);
    return B_EC_FILE_OPEN_FAILED;
  }

  EVP_CIPHER_CTX *ctx = NULL;
  int length = 0;

  if (!(ctx = EVP_CIPHER_CTX_new())) {
    b_crypto_cipher_cleanup(NULL, in_file, out_file);
    return B_EC_CRYPTO_CTX_FAILED;
  }

  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, cp->key, cp->iv)) {
    b_crypto_cipher_cleanup(ctx, in_file, out_file);
    return B_EC_CRYPTO_INIT_FAILED;
  }

  size_t bytes_read = 0;
  uchar_t buffer[B_CRYPTO_BUFFER_SIZE] = {0};
  uchar_t encrypted_buffer[B_CRYPTO_BUFFER_SIZE * 2] = {0};

  while ( (bytes_read = fread(buffer, 1, B_CRYPTO_BUFFER_SIZE, in_file)) > 0 ) {
    if (1 != EVP_EncryptUpdate(ctx, encrypted_buffer, &length, buffer, bytes_read)) {
      b_crypto_cipher_cleanup(ctx, in_file, out_file);
      return B_EC_CRYPTO_UPDATE_FAILED;
    }

    fwrite(encrypted_buffer, 1, length, out_file);
  }

  if (1 != EVP_EncryptFinal_ex(ctx, encrypted_buffer, &length)) {
    b_crypto_cipher_cleanup(ctx, in_file, out_file);
    return B_EC_CRYPTO_FINAL_FAILED;
  }
  fwrite(encrypted_buffer, 1, length, out_file);

  b_crypto_cipher_cleanup(ctx, in_file, out_file);
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
    b_crypto_cipher_cleanup(NULL, in_file, NULL);
    return B_EC_FILE_OPEN_FAILED;
  }

  EVP_CIPHER_CTX *ctx = NULL;
  int length = 0;

  if (!(ctx = EVP_CIPHER_CTX_new())) {
    b_crypto_cipher_cleanup(ctx, in_file, out_file);
    return B_EC_CRYPTO_CTX_FAILED;
  }

  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, cp->key, cp->iv)) {
    b_crypto_cipher_cleanup(ctx, in_file, out_file);
    return B_EC_CRYPTO_INIT_FAILED;
  }

  size_t bytes_read = 0;
  uchar_t buffer[B_CRYPTO_BUFFER_SIZE] = {0};
  uchar_t decrypted_buffer[B_CRYPTO_BUFFER_SIZE * 2] = {0};

  while ( (bytes_read = fread(buffer, 1, B_CRYPTO_BUFFER_SIZE, in_file)) > 0 ) {
    if (1 != EVP_DecryptUpdate(ctx, decrypted_buffer, &length, buffer, bytes_read)) {
      b_crypto_cipher_cleanup(ctx, in_file, out_file);
      return B_EC_CRYPTO_UPDATE_FAILED;
    }

    fwrite(decrypted_buffer, 1, length, out_file);
  }

  if (1 != EVP_DecryptFinal_ex(ctx, decrypted_buffer, &length)) {
    b_crypto_cipher_cleanup(ctx, in_file, out_file);
    return B_EC_CRYPTO_FINAL_FAILED;
  }
  fwrite(decrypted_buffer, 1, length, out_file);

  b_crypto_cipher_cleanup(ctx, in_file, out_file);
  return B_EC_SUCCESS;
}

void b_crypto_cipher_cleanup(EVP_CIPHER_CTX *ctx, FILE *in_file, FILE *out_file) {
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

void b_crypto_sha_cleanup(EVP_MD_CTX *ctx, FILE *in_file, FILE *out_file) {
  if (ctx) {
    EVP_MD_CTX_free(ctx);
  }

  if (in_file) {
    fclose(in_file);
  }

  if (out_file) {
    fclose(out_file);
  }
}
