
#ifndef BOX_H_
#define BOX_H_

#include <bits/stdc++.h>

#include <cstdlib>
#include <exception>
#include <filesystem>
#include <set>
#include <vector>

#include "sisAuth.hpp"
#include "sisIO.hpp"

#define LOG_FILE_NAME "boxLog.txt"
#define BOX_DIR ".box"

#define FLIP_FILE_KEY 128

#define FLIP_PATH_ODD_KEY 3
#define FLIP_PATH_EVEN_KEY 8
#define FLIP_PATH_UNWRAP_BIAS 26
#define FLIP_PATH_WRAP_BIAS 0

#define ANSI_CLEAR_LINE "\33[2K\r"
#define ANSI_MOVE_UP "\033[F"

class Box {
 private:
  // box properties

  const std::filesystem::path HOME_DIR =
      std::filesystem::path(std::getenv("HOME"));
  const std::filesystem::path LOG_FILE = HOME_DIR / LOG_FILE_NAME;
  const std::filesystem::path ROOT_PATH;
  const std::filesystem::path BOX_PATH;
  const std::filesystem::path BOX_CONFIG_FILE;
  std::set<std::string> ignores;
  void prepareTagList(const std::string &_tagString);

  bool isWrapped;
  bool isBoxxed;
  bool isSubBoxxed;
  std::string PASSWORD_HASH;

  // query

  bool pathIsIgnored(const std::filesystem::path &_path);
  bool authenticateUser(const std::string &_PASSWORD_HASH);
  std::filesystem::path validateBoxPath(const std::filesystem::path &_path);

  // file flipping

  const std::set<std::string> SIMPLE_FLIP_EXTS;
  void singleByteFlip(std::fstream &_stream);
  void multyByteFlip(std::fstream &_stream,
                     const std::filesystem::path &_filePath);
  int flipFile(const std::filesystem::path &_filePath);
  int flipAllFilesHelper(const std::filesystem::path &_path);
  int flipAllFiles();

  // file indexing

  const std::string getFileHash(const std::filesystem::path &_filePath);
  std::filesystem::path indexFile(const std::filesystem::path &_filePath);
  int indexAllFilesHelper(const std::filesystem::path &_path);
  int indexAllFiles();

  // path flipping

  std::filesystem::path flipPath(const std::filesystem::path &_path);
  int flipAllPathsHelper(const std::filesystem::path &_directory);
  int flipAllPaths();

  // tags

  std::vector<std::string> parseTags(const std::filesystem::path &_path);
  std::string joinTags(const std::vector<std::string> &_tags);

  SisIO io;
  SisAuth auth;

  // exceptions

  class pathNotFoundException : public std::exception {
   public:
    pathNotFoundException(const std::filesystem::path &_path) : PATH(_path) {}
    const std::filesystem::path PATH;

    std::string what() { return ("Could not find " + PATH.string()); }
  };

 public:
  Box(const std::filesystem::path &_rootPath);
  int wrap();
  int create();
  int unwrap();
  int index();
  int addTag(const std::filesystem::path &_path);
  int removeTag(const std::filesystem::path &_path);
  ~Box();
  std::vector<std::string> tagList;
};

#endif  // !BOX_H_
