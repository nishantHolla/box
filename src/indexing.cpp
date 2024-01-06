
#include <algorithm>
#include <cstdio>

#include "box.hpp"

const std::string Box::getFileHash(const std::filesystem::path &_filePath) {
  if (std::filesystem::is_regular_file(_filePath) == false) return "fffff";

  const std::string COMMAND =
      "openssl sha256 \"" + _filePath.string() + "\" | awk '{print $NF}'";
  FILE *process = popen(COMMAND.c_str(), "r");
  if (!process) return "fffff";

  std::string result;
  for (int i = 0; i < 6; i++) result += std::getc(process);

  pclose(process);
  return result;
}

std::filesystem::path Box::indexFile(const std::filesystem::path &_filePath) {
  const std::string FILE_NAME = _filePath.filename();
  const std::string FILE_EXT = _filePath.extension();
  const std::string FILE_HASH = getFileHash(_filePath);

  int separatorCount = std::count(FILE_NAME.begin(), FILE_NAME.end(), '.');
  std::string newName = "";
  if (separatorCount == 0)
    newName = FILE_HASH;
  else if (separatorCount == 1)
    newName = FILE_HASH + FILE_EXT;
  else {
    int lastSeparator = FILE_NAME.find_last_of('.');
    int secondLastSeparator = FILE_NAME.find_last_of('.', lastSeparator - 1);
    std::string TAGS = FILE_NAME.substr(0, secondLastSeparator);  // TODO
    newName = TAGS + "." + FILE_HASH + FILE_EXT;
  }

  return _filePath.parent_path() / newName;
}

int Box::indexAllFilesHelper(const std::filesystem::path &_path) {
  for (auto &entry : std::filesystem::recursive_directory_iterator(_path)) {
    if (entry.is_regular_file() == false) continue;

    if (pathIsIgnored(entry.path())) continue;

    const std::string INDEXED_NAME = indexFile(entry.path());
    if (INDEXED_NAME != entry.path()) {
      io.output(SisIO::messageType::info,
                "Indexing file " + entry.path().string());
      std::filesystem::rename(entry.path(), INDEXED_NAME);
    }
  }

  return 0;
}

int Box::indexAllFiles() {
  io.output(SisIO::messageType::info, "Started job: File indexing");
  indexAllFilesHelper(ROOT_PATH);
  io.output(SisIO::messageType::okay, "Finished job: File indexing");
  return 0;
}
