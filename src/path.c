#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include "box.h"

B_EXIT_CODE b_path_abs(const char *in, char *out) {
  if (realpath(in, out) == NULL) {
    return B_EC_INVALID_ARG;
  }
  else {
    return B_EC_SUCCESS;
  }
}

B_PATH_STAT b_path_stat(const char *path) {
  struct stat path_stat;

  if (lstat(path, &path_stat) == -1) {
    return B_PATH_ERROR;
  } 

  if (S_ISLNK(path_stat.st_mode)) {
    if (stat(path, &path_stat) == -1) {
      return B_PATH_ERROR;
    }

    if (S_ISREG(path_stat.st_mode)) {
      return B_PATH_LINK_FILE;
    }
    else if (S_ISDIR(path_stat.st_mode)) {
      return B_PATH_LINK_DIR;
    }
    else {
      return B_PATH_UNKNOWN;
    }
  }
  else if (S_ISREG(path_stat.st_mode)) {
    return B_PATH_FILE;
  }
  else if (S_ISDIR(path_stat.st_mode)) {
    return B_PATH_DIR;
  }
  else {
    return B_PATH_UNKNOWN;
  }
}

B_EXIT_CODE b_path_concat(const char *left, const char *right, char *out) {
  strncpy(out, left, B_PATH_MAX_LENGTH);
  const int left_len = strnlen(out, B_PATH_MAX_LENGTH);

  if (left_len >= B_PATH_MAX_LENGTH - 1) {
    return B_EC_INVALID_ARG;
  }

  if (out[left_len-1] != '/') {
    out[left_len] = '/';
  }

  strncat(out, right, B_PATH_MAX_LENGTH - left_len);
  return B_EC_SUCCESS;
}
