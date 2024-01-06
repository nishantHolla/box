
#include "box.hpp"

std::filesystem::path Box::flipPath(const std::filesystem::path &_path) {
  if (std::filesystem::exists(_path) == false) {
    io.log(SisIO::messageType::error,
           "Could not flip non existent path " + _path.string(),
           "flipPath method");
    return {};
  }

  const std::filesystem::path path = std::filesystem::canonical(_path);
  const std::filesystem::path parentPath = path.parent_path();
  const std::string baseName = path.filename();
  std::string newName = "";
  const int bias = isWrapped ? 26 : 0;

  for (int i = 0, s = baseName.size(); i < s; i++) {
    if (baseName[i] < 'A' || baseName[i] > 'z') {
      newName += baseName[i];
      continue;
    }

    int key = FLIP_PATH_ODD_KEY;
    if (i % 2 == 0) key = FLIP_PATH_EVEN_KEY;

    key = std::abs(key - bias);

    if (baseName[i] >= 'A' && baseName[i] <= 'Z')
      newName += ((baseName[i] + key - 'A') % 26 + 'A');
    else
      newName += ((baseName[i] + key - 'a') % 26 + 'a');
  }

  const std::filesystem::path newPath = parentPath / newName;
  std::filesystem::rename(path, newPath);
  return newPath;
}

int Box::flipAllPathsHelper(const std::filesystem::path &_directory) {
  for (auto entry : std::filesystem::directory_iterator(_directory)) {
    if (entry.is_symlink()) continue;

    if (pathIsIgnored(entry.path())) continue;

    io.output(SisIO::messageType::info,
              "Flipping path " + entry.path().string());
    std::filesystem::path newPath = flipPath(entry.path());

    if (entry.is_directory()) flipAllPathsHelper(newPath);
  }
  return 0;
}

int Box::flipAllPaths() {
  io.output(SisIO::messageType::info, "Started job: Path flipping");
  flipAllPathsHelper(ROOT_PATH);
  io.output(SisIO::messageType::okay, "Finished job: Path flipping");
  return 0;
}
