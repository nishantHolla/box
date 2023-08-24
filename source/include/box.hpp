
#ifndef BOX_H_
#define BOX_H_

#include <bits/stdc++.h>
#include <filesystem>
#include <cstdlib>
#include <vector>
#include <set>

#include "sisIO.hpp"

#define LOG_FILE_NAME "boxLog.txt"

#define FLIP_FILE_KEY 128

#define FLIP_PATH_ODD_KEY 3
#define FLIP_PATH_EVEN_KEY 8
#define FLIP_PATH_UNWRAP_BIAS 26
#define FLIP_PATH_WRAP_BIAS 0

#define ANSI_CLEAR_LINE "\33[2K\r"
#define ANSI_MOVE_UP "\033[F"

class Box {
private:
	const std::filesystem::path HOME_DIR = std::filesystem::path(std::getenv("HOME"));
	const std::filesystem::path LOG_FILE = HOME_DIR / LOG_FILE_NAME;
	const std::filesystem::path ROOT_PATH;
	const std::set<std::string> SIMPLE_FLIP_EXTS;
	std::set<std::string> ignores;

	int flipFile(const std::filesystem::path& _filePath);
	void singleByteFlip(std::fstream& _stream);
	void multyByteFlip(std::fstream& _stream, const std::filesystem::path& _filePath);

	std::filesystem::path flipPath(const std::filesystem::path& _path, const int _bias);

	bool pathIsIgnored(const std::filesystem::path& _path);
	int flipAllPathsHelper(const std::filesystem::path& _directory);
	int flipPathBias;

	SisIO io;

public:
	Box(const std::filesystem::path& _rootPath);
	int flipAllFiles();
	int flipAllPaths();
	~Box();
};

#endif // !BOX_H_
