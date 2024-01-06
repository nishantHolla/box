
#include <string>

#include "box.hpp"

std::string shiftArgs(int *_argc, char **_argv[]);

int main(int argc, char *argv[]) {
  if (argc < 3) {
    std::cout << "Usage: <program_name> <action> <box_root_path>\n";
    std::cout << "    Actions:\n";
    std::cout << "        create: create a new box in an unboxed directory.\n";
    std::cout << "        wrap: encrypt a box.\n";
    std::cout << "        unwrap: decrypt a box.\n";
    std::cout << "        index: index the box.\n";
    std::cout << "        addTag: add a tag to a file.\n";
    std::cout << "        removeTag: remove a tag from a file.\n";
    return 1;
  }

  const std::string PROGRAM = shiftArgs(&argc, &argv);
  const std::string ACTION = shiftArgs(&argc, &argv);
  const std::string TARGET = shiftArgs(&argc, &argv);

  Box box(TARGET);
  int exitCode = 2;

  if (ACTION == "create")
    exitCode = box.create();

  else if (ACTION == "wrap")
    exitCode = box.wrap();

  else if (ACTION == "unwrap")
    exitCode = box.unwrap();

  else if (ACTION == "index")
    exitCode = box.index();

  else if (ACTION == "addTag")
    exitCode = box.addTag(TARGET);

  else if (ACTION == "removeTag")
    exitCode = box.removeTag(TARGET);

  return exitCode;
}

std::string shiftArgs(int *_argc, char **_argv[]) {
  if (_argc == 0) return "";

  const std::string ARGUMENT = (*_argv)[0];
  (*_argc)--;
  (*_argv)++;
  return ARGUMENT;
}
